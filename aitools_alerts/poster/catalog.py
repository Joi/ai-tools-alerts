"""The catalog lane (ai-tools-alerts#q03f): every in-scope advisory's block, as a root
in the catalog channel, for machines to match (design section "1. Two outputs").

Two steps:

- ``snapshot`` runs under the ledger lock, after planning and before the digest
  (which drops the notices it lists from the held list), and only reads: each ledger
  thread whose product is in scope and starts at its level, and each held notice,
  in memory.
- ``send_pass`` runs after the ledger lock is released and the checkpoint is signed,
  under the catalog's own lock (``Config.catalog_lock``, waited for at most
  ``LOCK_WAIT`` seconds). It merges the snapshot into the inventory
  (``Config.catalog_known``, which keeps the latest snapshot's advisory per key and
  outlives the held list), then posts a root for every key whose advisory differs from the one
  last sent (``Config.catalog_state``), at most ``MAX_PER_RUN`` attempts a run and none after
  ``DEADLINE`` seconds. No catalog file is read or written under the ledger lock, so
  nothing here can delay an alert post, the checkpoint or the next run.

A key is one advisory for one product: ``<product name>|<advisory id casefolded>``.
Every catalog post is a root carrying the whole block; a changed advisory posts a new
root, and a reader takes the newest root per advisory id and product (for an
advisory that also has an alert thread, the alert thread governs). No replies, no
Japanese copy, and never ``signer.record_sent``: no checkpoint lists a catalog event,
because released readers refuse a checkpoint that names an event outside feed.json
and critical.json.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import sys
import time
from dataclasses import asdict, replace

from aitools_alerts import schema
from aitools_alerts.poster import compose, inputs, rules

MAX_PER_RUN = 20  # sends a pass; switching the lane on with a full ledger catches up over runs
DEADLINE = 120  # seconds after which a pass starts no new send
LOCK_WAIT = 60  # seconds a pass waits for another run's pass to finish
MAX_KEYS = 5000
MAX_FILE = 64 << 20  # read limit; the inventory is written within KEEP_BYTES of it
KEEP_BYTES = 48 << 20
VERSION = 1


def _say(msg: str) -> None:
    print(f"aitools-alerts-poster: catalog: {msg}", file=sys.stderr)


def key(product: str, adv_id: str) -> str:
    return f"{product}|{adv_id.casefold()}"


def fingerprint(adv: dict) -> str:
    return hashlib.sha256(json.dumps(adv, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def _valid(adv) -> dict | None:
    """The advisory as a validated dict with one product, or None."""
    try:
        a = schema.validate(adv)
    except (ValueError, TypeError):
        return None
    if compose.is_synthetic(a.id) or len(a.products) != 1 or not a.sources:
        return None
    return asdict(a)


def _scope(name):
    """The scope entry (or resolved component) a thread or held notice is filed under,
    by its name, or by an earlier name in an entry's ``formerly`` (wa6n: a thread keeps
    the name it was posted under, as ``Run._former`` does); None when the scope file has
    neither. A name is not always an identity (the entry Cursor matches "cursor ide"),
    so this is not ``scope_of``."""
    if not isinstance(name, str):
        return None
    entries = list(rules._default_index().values())
    hit = next((s for s in entries if s.name == name), None)
    if hit is None:
        old = next((s for s in entries if name in getattr(s, "formerly", ())), None)
        hit = replace(old, name=name, formerly=()) if old is not None else None
    return hit


def _in_scope(name) -> bool:
    return _scope(name) is not None


def snapshot(led, held) -> dict[str, dict]:
    """{key: advisory} for every ledger thread whose product is in scope now and starts
    at its level (the ruleset's channel_if lets an out product's high in; an out
    notice starts nothing, wa6n), and every held notice. A thread wins over a held
    notice under the same key. Synthetic and malformed advisories are left out."""
    out: dict[str, dict] = {}
    for h in held:
        a = _valid(h.get("adv")) if isinstance(h, dict) else None
        if a is not None and h.get("scope") == a["products"][0]["name"] and _in_scope(h["scope"]):
            out[key(h["scope"], a["id"])] = a
    for e in led.entries():
        scope = _scope(e.scope)
        a = _valid(e.advisory)
        if a is None or scope is None or not rules.starts(scope, e.level):
            continue
        out[key(e.scope, a["id"])] = a
    return out


def _read(path, field: str) -> dict:
    """The file's ``field`` map; a missing file is empty, a malformed one is empty with
    a line on stderr (the lane then sends again, which is harmless)."""
    try:
        doc = inputs.read_regular_json(path, MAX_FILE)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, RecursionError) as e:
        _say(f"{path.name} unreadable ({type(e).__name__}); starting empty")
        return {}
    if not (isinstance(doc, dict) and doc.get("v") == VERSION and isinstance(doc.get(field, {}), dict)):
        _say(f"{path.name} malformed; starting empty")
        return {}
    return doc.get(field, {})


_last = 0


def stamp() -> int:
    """The snapshot's order: wall-clock nanoseconds, read under the ledger lock, which
    no two runs hold at once (releasing and taking it again takes far longer than the
    clock's resolution); strictly increasing within one process."""
    global _last
    _last = max(time.time_ns(), _last + 1)
    return _last


def _encoded(doc) -> int:
    """The bytes ``inputs.write_json`` writes for ``doc`` (same encoder settings)."""
    return len(json.dumps(doc, indent=1, sort_keys=True).encode("utf-8"))


def remember(path, snap: dict, at: int = 0) -> int:
    """Merge a snapshot stamped ``at`` into the inventory; returns the number of keys
    kept. ``at`` is ``stamp()``, taken under the ledger lock, so two runs' snapshots
    never share one and the later run's is larger. A key the inventory holds from a
    later snapshot keeps that one: two runs' passes can merge in either order. Called under the catalog lock only.
    Bounded by MAX_KEYS and KEEP_BYTES, measured as written, the oldest first sight
    dropped first, so what is written is always readable (MAX_FILE)."""
    known = {k: a for k, a in _read(path, "known").items() if _valid(a) is not None}
    stamp = {k: t for k, t in _read(path, "at").items() if k in known and type(t) is int}
    for k, a in snap.items():
        if stamp.get(k, 0) <= at:  # equal: the same snapshot merged again
            known[k], stamp[k] = a, at
    known = {k: a for k, a in known.items() if _in_scope(a["products"][0]["name"])}
    order = sorted(known, key=lambda k: (known[k]["posted_at"], k), reverse=True)[:MAX_KEYS]  # newest first
    while True:
        doc = {"v": VERSION, "known": {k: known[k] for k in order}, "at": {k: stamp.get(k, 0) for k in order}}
        if _encoded(doc) <= KEEP_BYTES or not order:
            break
        order = order[:len(order) * 9 // 10]  # the oldest tenth goes, until it fits
    inputs.write_json(path, doc)
    return len(order)


def _lock(fh, clock, wait) -> bool:
    start = clock()
    while True:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            if clock() - start >= wait:
                return False
            time.sleep(1)


def _sent_ok(v) -> bool:
    return (isinstance(v, dict) and set(v) == {"event", "digest"} and isinstance(v["digest"], str)
            and (v["event"] is None or isinstance(v["event"], str)))


def send_pass(config, channel_id: str, send, snap: dict | None = None, at: int = 0, clock=time.monotonic,
              wait: float | None = None) -> str:
    """Merge ``snap`` into the inventory, then post what the inventory holds and the
    catalog channel lacks. Returns ``<sent>/<waiting>``, or ``busy`` when another
    pass held the lock for ``wait`` seconds (this run's snapshot is then not merged;
    the next run's snapshot carries every thread and every notice still held). ``send(channel_id, text, None)`` is the run's
    relay sender. A failed or unknown send ends the pass and records nothing (the next
    run sends again); a refused one, or one compose refuses, records the advisory so
    the same block is not tried again."""
    config.catalog_lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(config.catalog_lock, "a") as fh:
        if not _lock(fh, clock, LOCK_WAIT if wait is None else wait):
            return "busy"
        if snap is not None:
            remember(config.catalog_known, snap, at)
        start = clock()  # the deadline counts sends, not the wait for the lock
        known = {k: a for k, a in _read(config.catalog_known, "known").items() if _valid(a) is not None}
        sent = {k: v for k, v in _read(config.catalog_state, "sent").items() if k in known and _sent_ok(v)}

        def save():
            inputs.write_json(config.catalog_state, {"v": VERSION, "sent": sent})

        todo = sorted((k for k in known if sent.get(k, {}).get("digest") != fingerprint(known[k])),
                      key=lambda k: (known[k]["posted_at"], k))
        n = tries = 0
        for k in todo:
            if tries >= MAX_PER_RUN or clock() - start >= DEADLINE:  # attempts, refused ones too
                break
            d = fingerprint(known[k])
            try:
                text = compose.catalog_post(known[k])
            except ValueError:
                sent[k] = {"event": None, "digest": d}
                save()
                continue
            tries += 1
            r = send(channel_id, text, None)
            if r.outcome == "ok":
                sent[k] = {"event": r.event_id, "digest": d}
                n += 1
            elif r.outcome == "refused":
                sent[k] = {"event": None, "digest": d}
                _say(f"{k} refused by the relay: {r.message}")
            else:
                _say(f"send {r.outcome}; the rest waits for the next run")
                break
            save()
        save()  # the pruned map, even when nothing was sent
        waiting = sum(1 for k in known if sent.get(k, {}).get("digest") != fingerprint(known[k]))
        return f"{n}/{waiting}"
