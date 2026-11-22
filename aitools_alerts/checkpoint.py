"""The signed checkpoint: which events exist, said by a key the mirror does not hold.

Each event is signed; the set of events is not. Two more signed documents,
published beside ``manifest.json``, close that gap. Neither is ever sent to
the relay, and the released v0.1.4 reader fetches neither.

The **checkpoint key certificate** (``checkpoint-key.json``) is signed by the
trust root. It names the one key that may sign checkpoints, is bound to one
manifest by that manifest's event id, and expires. Content::

    {"v": 1, "manifest_id", "manifest_version", "checkpoint_key",
     "issued_at", "expires_at"}

The **checkpoint** (``checkpoint.json``) is signed by the certified key, off
the machine that serves the mirror, on a schedule. It lists the ids of the
events its signer vouches for. Content::

    {"v": 1, "seq", "valid_until", "manifest_id", "manifest_version", "events"}

Both are Nostr events of kind 30078 with one ``d`` tag each, so neither can
pass for the other or for the manifest. Use them in this order: ``load_*``
(shape only), ``verify_*`` (signature, by the root or by the certificate's
key), then ``*_problem`` (the right manifest, the clock), and ``*_order``
against what was accepted before. A loaded but unverified document proves
nothing.

``v`` is the format version. Another value is refused as "unsupported
format": a later format that adds a restriction must fail closed here, not be
ignored. Within version 1, content keys this module does not know are ignored.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from . import nostr
from .manifest import Manifest

__all__ = ["KIND", "CERT_D_TAG", "CHECKPOINT_D_TAG", "VERSION", "MAX_CERT_BYTES", "MAX_CHECKPOINT_BYTES",
           "MAX_EVENT_IDS", "MAX_AHEAD_S", "MAX_VALID_S", "DEFAULT_VALID_S", "CheckpointError",
           "Cert", "Checkpoint", "load_cert", "verify_cert", "cert_problem", "cert_order",
           "load_checkpoint", "verify_checkpoint", "checkpoint_problem", "checkpoint_order",
           "fresh_until", "build_cert", "build_checkpoint"]

KIND = 30078
CERT_D_TAG = "aitools-alerts-checkpoint-key"
CHECKPOINT_D_TAG = "aitools-alerts-checkpoint"
VERSION = 1
MAX_CERT_BYTES = 16 << 10
MAX_CHECKPOINT_BYTES = 256 << 10
MAX_EVENT_IDS = 2000
MAX_AHEAD_S = 600  # pull.MAX_AHEAD_S; tests/test_checkpoint.py checks the two are equal
MAX_VALID_S = 2 * 86400  # the longest validity a reader honours, whatever the signer wrote
DEFAULT_VALID_S = 86400
MAX_INT = 2**31 - 1
MAX_SEQ = 2**53 - 1  # an exact integer in every JSON reader; room for any numbering a signer picks
_ISO_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
MAX_TIME = 253402300799  # 9999-12-31T23:59:59Z
_EVENT_KEYS = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})
_ISO = "%Y-%m-%dT%H:%M:%SZ"


class CheckpointError(ValueError):
    """A certificate or checkpoint is malformed, or cannot be built as asked."""


@dataclass(frozen=True)
class Cert:
    event: dict
    manifest_id: str
    manifest_version: int
    checkpoint_key: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class Checkpoint:
    event: dict
    seq: int
    created_at: int
    valid_until: int
    manifest_id: str
    manifest_version: int
    events: frozenset


# ---------------------------------------------------------------- parsing

def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise CheckpointError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _reject_constant(name):
    raise CheckpointError(f"non-standard JSON constant {name}")


def _json(text: str):
    try:
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except CheckpointError:
        raise
    except RecursionError:
        raise CheckpointError("JSON nested too deeply") from None
    except ValueError:  # not JSON, or an integer over Python's digit limit
        raise CheckpointError("not JSON") from None


def _read(src, limit: int, what: str) -> str:
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        try:
            with open(src, "rb") as f:
                data = f.read(limit + 1)
        except OSError as e:
            raise CheckpointError(f"cannot read {what}: {e.strerror}") from None
    else:
        raise CheckpointError(f"{what} source must be a path or bytes")
    if len(data) > limit:
        raise CheckpointError(f"{what} larger than {limit} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise CheckpointError(f"{what} is not UTF-8") from None


def _event(ev, d_tag: str, what: str) -> dict:
    """The decoded content of an event of the right shape, kind and d tag."""
    if not isinstance(ev, dict) or set(ev) != _EVENT_KEYS:
        raise CheckpointError(f"{what} must be an event with exactly the NIP-01 keys")
    try:
        nostr._check_shape(ev)
    except ValueError as e:
        raise CheckpointError(f"{what}: {e}") from None
    if not nostr._is_hex(ev["id"], 32) or not nostr._is_hex(ev["sig"], 64):
        raise CheckpointError(f"{what}: id and sig must be lowercase hex")
    if ev["kind"] != KIND:
        raise CheckpointError(f"{what}: kind must be {KIND}")
    if ev["tags"] != [["d", d_tag]]:
        raise CheckpointError(f'{what}: tags must be exactly [["d", "{d_tag}"]]')
    c = _json(ev["content"])
    if not isinstance(c, dict):
        raise CheckpointError(f"{what}: content must be an object")
    v = c.get("v")
    if type(v) is not int or v != VERSION:
        raise CheckpointError(f"{what}: unsupported format (v must be {VERSION}); upgrade aitools-alerts")
    return c


def _int(c: dict, key: str, lo: int, hi: int, what: str) -> int:
    v = c.get(key)
    if type(v) is not int or not lo <= v <= hi:  # a bool is not an int here
        raise CheckpointError(f"{what}: {key} must be an integer in {lo}..{hi}")
    return v


def _hex(c: dict, key: str, what: str) -> str:
    v = c.get(key)
    if not nostr._is_hex(v, 32):
        raise CheckpointError(f"{what}: {key} must be 64 lowercase hex characters")
    return v


def _time(c: dict, key: str, what: str) -> int:
    v = c.get(key)
    try:
        if not isinstance(v, str) or not _ISO_RE.fullmatch(v):  # ASCII digits, upper-case T and Z only
            raise ValueError
        return int(datetime.strptime(v, _ISO).replace(tzinfo=timezone.utc).timestamp())
    except ValueError:
        raise CheckpointError(f"{what}: {key} must be YYYY-MM-DDTHH:MM:SSZ") from None


def _iso(t: int) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime(_ISO)


def _key_ok(pub) -> bool:
    return nostr._is_hex(pub, 32) and nostr._lift_x(int(pub, 16)) is not None


# ---------------------------------------------------------------- certificate

def _parse_cert(ev) -> tuple:
    c = _event(ev, CERT_D_TAG, "certificate")
    key = _hex(c, "checkpoint_key", "certificate")
    if not _key_ok(key):
        raise CheckpointError("certificate: checkpoint_key is not an x-only public key")
    issued, expires = _time(c, "issued_at", "certificate"), _time(c, "expires_at", "certificate")
    if ev["created_at"] != issued:
        raise CheckpointError("certificate: created_at must equal issued_at")
    if expires <= issued:
        raise CheckpointError("certificate: expires_at must be after issued_at")
    return (_hex(c, "manifest_id", "certificate"), _int(c, "manifest_version", 1, MAX_INT, "certificate"),
            key, issued, expires)


def load_cert(src) -> Cert:
    """Parse a certificate from a path or bytes. Does NOT verify the signature."""
    ev = _json(_read(src, MAX_CERT_BYTES, "certificate"))
    fields = _parse_cert(ev)  # the shape first: only a well-formed event is copied
    return Cert(copy.deepcopy(ev), *fields)


def verify_cert(cert: Cert, root_pubkey: str) -> bool:
    """True only if the certificate's event is signed by ``root_pubkey`` and
    says exactly what ``cert`` says. Never raises."""
    try:
        if not isinstance(cert, Cert) or not nostr._is_hex(root_pubkey, 32):
            return False
        ev = cert.event
        if not isinstance(ev, dict) or ev.get("pubkey") != root_pubkey:
            return False
        if _parse_cert(ev) != (cert.manifest_id, cert.manifest_version, cert.checkpoint_key,
                               cert.issued_at, cert.expires_at):
            return False
        return nostr.verify_event(ev)
    except (ValueError, TypeError, KeyError, RecursionError):
        return False


def cert_problem(cert: Cert, m: Manifest, now: float) -> str | None:
    """Why a verified certificate cannot be used for manifest ``m`` at ``now``,
    or None. The manifest is bound by its event id, never by version alone."""
    if cert.manifest_id != m.event.get("id"):
        return "other manifest"
    if cert.issued_at > now + MAX_AHEAD_S:
        return "dated ahead"
    if now > cert.expires_at:
        return "expired"
    return None


def cert_order(new: Cert, old: Cert | None) -> str | None:
    """Why ``new`` may not replace the accepted certificate ``old``, or None.
    The same event again is fine; otherwise it must be issued later."""
    if old is None or new.event.get("id") == old.event.get("id"):
        return None
    if new.issued_at < old.issued_at:
        return "older certificate"
    if new.issued_at == old.issued_at:
        return "conflicting certificate"
    return None


def build_cert(root_sec: str, m: Manifest, checkpoint_key: str, issued_at: int, expires_at: int) -> dict:
    """The signed certificate event naming ``checkpoint_key`` for manifest ``m``."""
    if not _key_ok(checkpoint_key):
        raise CheckpointError("checkpoint_key is not an x-only public key (64 lowercase hex)")
    if not all(type(t) is int and 0 <= t <= MAX_TIME for t in (issued_at, expires_at)) or expires_at <= issued_at:
        raise CheckpointError("expires_at must be after issued_at, both whole seconds")
    content = {"v": VERSION, "manifest_id": m.event["id"], "manifest_version": m.version,
               "checkpoint_key": checkpoint_key, "issued_at": _iso(issued_at), "expires_at": _iso(expires_at)}
    ev = nostr.sign_event(root_sec, {"created_at": issued_at, "kind": KIND, "tags": [["d", CERT_D_TAG]],
                                     "content": json.dumps(content, sort_keys=True, separators=(",", ":"))})
    _parse_cert(ev)
    return ev


# ---------------------------------------------------------------- checkpoint

def _parse_checkpoint(ev) -> tuple:
    c = _event(ev, CHECKPOINT_D_TAG, "checkpoint")
    ids = c.get("events")
    if not isinstance(ids, list) or len(ids) > MAX_EVENT_IDS:
        raise CheckpointError(f"checkpoint: events must be a list of at most {MAX_EVENT_IDS} ids")
    if not all(nostr._is_hex(i, 32) for i in ids):
        raise CheckpointError("checkpoint: every event id must be 64 lowercase hex characters")
    if any(a >= b for a, b in zip(ids, ids[1:])):
        raise CheckpointError("checkpoint: event ids must be sorted, each once")
    if ev["created_at"] > MAX_TIME:
        raise CheckpointError("checkpoint: created_at is past the year 9999")
    return (_int(c, "seq", 1, MAX_SEQ, "checkpoint"), ev["created_at"],
            _int(c, "valid_until", 0, MAX_TIME, "checkpoint"), _hex(c, "manifest_id", "checkpoint"),
            _int(c, "manifest_version", 1, MAX_INT, "checkpoint"), frozenset(ids))


def load_checkpoint(src) -> Checkpoint:
    """Parse a checkpoint from a path or bytes. Does NOT verify the signature."""
    ev = _json(_read(src, MAX_CHECKPOINT_BYTES, "checkpoint"))
    fields = _parse_checkpoint(ev)
    return Checkpoint(copy.deepcopy(ev), *fields)


def verify_checkpoint(cp: Checkpoint, cert: Cert) -> bool:
    """True only if the checkpoint's event is signed by the key ``cert`` names
    and says exactly what ``cp`` says. Verify ``cert`` first. Never raises."""
    try:
        if not isinstance(cp, Checkpoint) or not isinstance(cert, Cert):
            return False
        ev = cp.event
        if not isinstance(ev, dict) or ev.get("pubkey") != cert.checkpoint_key:
            return False
        if _parse_checkpoint(ev) != (cp.seq, cp.created_at, cp.valid_until, cp.manifest_id,
                                     cp.manifest_version, cp.events):
            return False
        return nostr.verify_event(ev)
    except (ValueError, TypeError, KeyError, RecursionError):
        return False


def checkpoint_problem(cp: Checkpoint, m: Manifest, now: float) -> str | None:
    """Why a verified checkpoint cannot be used with manifest ``m`` at ``now``,
    or None. Freshness is separate: see ``fresh_until``."""
    if cp.manifest_id != m.event.get("id"):
        return "other manifest"
    if cp.created_at > now + MAX_AHEAD_S:
        return "dated ahead"
    return None


def fresh_until(cp: Checkpoint) -> int:
    """The last second ``cp`` counts as fresh: its valid_until, but never more
    than MAX_VALID_S after it was signed, so one checkpoint signed with a
    stolen key and a far valid_until is worth two days, not years."""
    return min(cp.valid_until, cp.created_at + MAX_VALID_S)


def checkpoint_order(new: Checkpoint, old: Checkpoint | None) -> str | None:
    """Why ``new`` may not replace the accepted checkpoint ``old``, or None.
    ``seq`` counts per signing key. Same key: the same event again is fine; a
    lower seq, or a higher seq dated earlier, is "older checkpoint"; the same
    seq with another id is "conflicting checkpoint" (a stolen key or a split
    view). Another key (a new certificate named it): seq starts again, and the
    checkpoint must not be dated before the accepted one."""
    if old is None or new.event.get("id") == old.event.get("id"):
        return None
    if new.event.get("pubkey") != old.event.get("pubkey"):
        return "older checkpoint" if new.created_at < old.created_at else None
    if new.seq == old.seq:
        return "conflicting checkpoint"
    if new.seq < old.seq or new.created_at < old.created_at:
        return "older checkpoint"
    return None


def build_checkpoint(sec: str, m: Manifest, seq: int, event_ids, now: int,
                     valid_s: int = DEFAULT_VALID_S) -> dict:
    """The signed checkpoint event number ``seq`` over ``event_ids`` (sorted
    and de-duplicated here), valid for ``valid_s`` seconds from ``now``."""
    ids = list(event_ids)
    if not all(nostr._is_hex(i, 32) for i in ids):
        raise CheckpointError("every event id must be 64 lowercase hex characters")
    ids = sorted(set(ids))
    if len(ids) > MAX_EVENT_IDS:
        raise CheckpointError(f"more than {MAX_EVENT_IDS} event ids")
    if type(seq) is not int or not 1 <= seq <= MAX_SEQ:
        raise CheckpointError(f"seq must be an integer in 1..{MAX_SEQ}")
    if type(now) is not int or type(valid_s) is not int or valid_s < 1 or not 0 <= now <= MAX_TIME - valid_s:
        raise CheckpointError("now and valid_s must be whole seconds, valid_s at least 1")
    content = {"v": VERSION, "seq": seq, "valid_until": now + valid_s, "manifest_id": m.event["id"],
               "manifest_version": m.version, "events": ids}
    ev = nostr.sign_event(sec, {"created_at": now, "kind": KIND, "tags": [["d", CHECKPOINT_D_TAG]],
                                "content": json.dumps(content, sort_keys=True, separators=(",", ":"))})
    _parse_checkpoint(ev)
    return ev
