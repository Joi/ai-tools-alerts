"""What this poster signed, and the relay-bot events it did not (ai-tools-alerts#m729).

The relay-bot key signs every alert, and a copy of it exists outside the poster
machine. An event that key signed and this poster did not is evidence of theft. The
poster cannot revoke the key (that takes the trust root), but it signs the checkpoint,
and a reader applies only what a checkpoint lists: so it leaves such an event out
(``signer.run_checkpoint``) and says so once in the digest (``main.Run.digest``).
Its other reads of its copy of the mirror leave such an event out too (``own``,
through ``main.Run._own``; ai-tools-alerts#9cch).

The record, ``Config.sent_state``:

    {"since": int | None, "ids": {event id: time},
     "foreign": {event id: first seen}, "said": [event id]}

``ids``: every event id this poster signed, written before the send
(``transport.Relay(on_signed=)``), and what it took as its own when the record was
started. Never pruned: a root can leave the poster's copy of the mirror and return
with a new reply. ``since``: when the record was started; None until then, and
nothing is judged before. ``foreign``: the relay-bot events of the last check that
``ids`` does not hold, and those of earlier checks that left the mirror before a
digest reported them. ``said``: those a delivered digest has reported.

The record starts from what the caller hands over (``check(adopt=)``: the ids the
poster's own served checkpoint lists while that checkpoint is fresh, the ledger's and the owed ones), never from
what is on the mirror. A record that is lost or unreadable starts the same way, so
losing it cannot make the poster vouch for an event it had left out.

Every change is made under a lock of its own (``<record>.lock``): the catalog pass
sends, and so records, outside the ledger lock.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import sys
from pathlib import Path

from aitools_alerts import manifest, nostr, pull
from aitools_alerts.state import write_json

__all__ = ["load", "note", "holds", "started", "check", "own", "unsaid", "mark_said", "MAX_SAID"]

MAX_SAID = 200  # foreign ids one digest reports; more wait for the next
MAX_KEPT = 1000  # foreign ids no longer on the mirror that are kept until a digest has reported them
MAX_BYTES = 64 << 20
_KEYS = {"since", "ids", "foreign", "said"}


def _say(msg: str) -> None:
    print(f"aitools-alerts-poster: {msg}", file=sys.stderr)


def _empty() -> dict:
    return {"since": None, "ids": {}, "foreign": {}, "said": []}


def _when(v) -> bool:
    return type(v) is int and 0 <= v <= 2**53


def _times(v) -> bool:
    return isinstance(v, dict) and all(nostr._is_hex(i, 32) and _when(t) for i, t in v.items())


def load(path) -> dict:
    """The record; an empty one (nothing started) when the file is missing, and, with
    one line on stderr, when it is not a record. Raises OSError when the file is there
    and cannot be read: that may pass, and must not be answered by writing an empty
    record over it."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return _empty()
    try:
        rec = json.loads(data.decode("utf-8")) if data is not None and len(data) <= MAX_BYTES else None
    except (UnicodeDecodeError, ValueError, RecursionError):
        rec = None
    if (isinstance(rec, dict) and set(rec) == _KEYS and (rec["since"] is None or _when(rec["since"]))
            and _times(rec["ids"]) and _times(rec["foreign"]) and isinstance(rec["said"], list)
            and all(nostr._is_hex(i, 32) for i in rec["said"])):
        return rec
    _say(f"sent record {path} is unreadable; started again")
    return _empty()


@contextlib.contextmanager
def _locked(path):
    """Hold the record's own lock; the caller reads the record inside it."""
    path = os.fspath(path)
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    fd = os.open(path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _save(path, rec: dict) -> None:
    """Write the record and make the replacement durable: a send follows a ``note``, and
    a machine that stops must not come back with the record from before it."""
    write_json(Path(path), rec)
    _sync_dir(path)


def _sync_dir(path) -> None:
    fd = os.open(os.path.dirname(os.fspath(path)) or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def note(path, event_id, now: int) -> None:
    """Write down that this poster signed ``event_id``. Raises OSError when it cannot
    be written: the caller must then not send the event."""
    if not nostr._is_hex(event_id, 32):
        return
    with _locked(path):
        rec = load(path)
        if event_id not in rec["ids"]:
            rec["ids"][event_id] = int(now)
            _save(path, rec)
        else:  # written by an earlier call that may have failed before it was durable
            _sync_dir(path)


def holds(path) -> set:
    """The recorded ids, for settling a send whose outcome is unknown by its id. Empty
    for a record that is missing, unreadable or not started: nothing is then settled
    from the mirror, and never by text alone, which a thief can copy."""
    try:
        rec = load(path)
    except OSError:
        return set()
    return set(rec["ids"]) if rec["since"] is not None else set()


def started(path) -> bool:
    """Whether the record has been started: before that nothing is judged. False for
    a record that is there and cannot be read."""
    try:
        return load(path)["since"] is not None
    except OSError:
        return False


def own(path, events: dict, m, now: int, channels=None) -> dict:
    """``events`` ({id: event}, the poster's whole copy of the mirror) without the
    foreign ones (``check``, run here without ``adopt``: an unstarted record judges
    nothing and the copy comes back whole). The same mapping when none is foreign."""
    foreign = check(path, events.values(), m, now, channels=channels)
    return {i: e for i, e in events.items() if i not in foreign} if foreign else events


def check(path, events, m, now: int, adopt=None, channels=None) -> set:
    """The ids of the foreign events among ``events``: signed by a relay-bot key of
    manifest ``m``, bound to an alert channel, and not in the record. Every relay-bot
    key counts: one checkpoint key belongs to one poster with one ledger, so a
    relay-bot event this poster did not sign is not its to vouch for.

    ``adopt``: ids to take as signed when the record has not been started; it is then
    started. Without it an unstarted record judges nothing and nothing is written.
    The record's ``foreign`` and ``said`` are brought up to date. When the record
    cannot be written, that is said on stderr and the result still stands."""
    channels = pull.channel_ids() if channels is None else channels
    bots = {ev["id"] for ev in events if manifest.role_of(m, ev["pubkey"]) == "relay-bot"
            and pull._bound(ev, channels)}
    try:
        with _locked(path):
            return _check(path, bots, int(now), adopt)
    except OSError as e:
        _say(f"sent record {path} not written: {e.strerror or type(e).__name__}")
        return _check(path, bots, int(now), adopt, save=False)


def _check(path, bots: set, now: int, adopt, save: bool = True) -> set:
    try:
        rec = load(path)
    except OSError:
        rec = _empty()
    was = json.dumps(rec, sort_keys=True)
    if rec["since"] is None:
        if adopt is None:
            return set()
        took = [i for i in adopt if nostr._is_hex(i, 32)]
        for i in took:
            rec["ids"].setdefault(i, now)
        rec["since"] = now
        if save:
            _say(f"sent record {path}: started with {len(took)} ids "
                 "(the served checkpoint, the ledger, the owed list)")
    foreign = bots - set(rec["ids"])
    # One that left the mirror before any digest reported it is kept until one has: the
    # line is owed for it all the same (the newest MAX_KEPT of them).
    said = set(rec["said"])
    owed = sorted((i for i in rec["foreign"] if i not in foreign and i not in said and i not in rec["ids"]),
                  key=lambda i: (rec["foreign"][i], i))[-MAX_KEPT:]
    rec["foreign"] = {i: rec["foreign"].get(i, now) for i in sorted(foreign | set(owed))}
    rec["said"] = [i for i in rec["said"] if i in foreign]
    if save and json.dumps(rec, sort_keys=True) != was:
        _save(path, rec)
    return foreign


def unsaid(path) -> list:
    """The foreign ids no delivered digest has reported yet, at most MAX_SAID."""
    rec = load(path)
    said = set(rec["said"])
    return sorted(i for i in rec["foreign"] if i not in rec["ids"] and i not in said)[:MAX_SAID]


def mark_said(path, ids) -> None:
    """A delivered digest reported ``ids``. Raises OSError when it cannot be written:
    the next digest then says the line again."""
    with _locked(path):
        rec = load(path)
        new = [i for i in ids if i in rec["foreign"] and i not in rec["said"]]
        if new:
            rec["said"] += new
            _save(path, rec)
