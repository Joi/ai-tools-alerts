"""Sign the feed checkpoint on the poster machine (ai-tools-alerts#nfm3).

The checkpoint (``aitools_alerts.checkpoint``) lists the events that exist,
so that the mirror, which the relay VM serves, cannot leave one out
unnoticed. It is signed here, with a key that never reaches that VM, at the
end of every poster run, and delivered over the poster's ssh route to a
command that only stores it; the exporter verifies it before publishing.

What it vouches for: every event in the poster's verified copy of the
mirror inside the window, and every event this poster sent and the relay
acknowledged (``owed``) until the poster has seen it on the mirror. It does
not vouch for a curator's post the relay withheld before the poster ever saw
it, nor that the legitimate poster wrote an event signed by the bot key.

One checkpoint key belongs to one poster with one ledger.
"""

from __future__ import annotations

import json
import os
import stat
import sys

from aitools_alerts import TRUST_ROOT_PUBKEY
from aitools_alerts import checkpoint as cpt
from aitools_alerts import manifest, nostr, pull
from aitools_alerts.state import State, write_json

__all__ = ["run_checkpoint", "KeyFileError", "read_key", "keygen", "load_owed", "save_owed", "record_sent", "settle_owed",
           "window", "next_seq", "MAX_LISTED", "MAX_LISTED_BYTES", "OWED_S", "MARGIN_S", "ENVELOPE"]

# One checkpoint lists at most this much. The exporter must be able to serve
# two checkpoints' events at once while it moves from one to the next, and
# twice this is inside one channel's caps (2,000 events, 4 MiB).
MAX_LISTED = 990
MAX_LISTED_BYTES = 2 << 20
OWED_S = 72 * 3600  # an acknowledged post never seen on the mirror is dropped after this
MARGIN_S = 2 * 86400  # below the reader's retention, so no listed thread ages out on a reader mid-interval
ENVELOPE = 600  # bytes allowed for an event's id, key, signature and tags around its text
MAX_KEY_BYTES = 200


class KeyFileError(ValueError):
    """The checkpoint key file cannot be used. The message never holds the key."""


def read_key(path) -> str:
    """The checkpoint secret key (64 hex) from ``path``: an nsec or 64 hex in
    a regular file owned by this user that no one else can read. The checks
    run on the open file, so the file checked is the file read."""
    path = os.fspath(path)
    if not os.path.isabs(path):
        raise KeyFileError(f"checkpoint key file {path}: not an absolute path")
    try:
        # O_NONBLOCK: a FIFO with no writer must fail the checks below, not hang the run
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise KeyFileError(f"checkpoint key file {path}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise KeyFileError(f"checkpoint key file {path}: not a regular file")
        if st.st_uid != os.geteuid():
            raise KeyFileError(f"checkpoint key file {path}: not owned by the user running the poster")
        if st.st_mode & 0o077:
            raise KeyFileError(f"checkpoint key file {path}: readable by others (chmod 600)")
        data = os.read(fd, MAX_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_KEY_BYTES:
        raise KeyFileError(f"checkpoint key file {path}: too long to be a key")
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    if text.startswith("nsec1"):
        try:
            return nostr.nsec_to_hex(text)
        except ValueError:
            pass
    elif nostr._is_hex(text, 32) and 1 <= int(text, 16) < nostr.N:
        return text
    raise KeyFileError(f"checkpoint key file {path}: not a secret key (an nsec or 64 hex characters)")


def keygen(path) -> str:
    """Create the key file (mode 600, never replacing one) and return the npub."""
    path = os.fspath(path)
    if not os.path.isabs(path):
        raise KeyFileError(f"checkpoint key file {path}: not an absolute path")
    sec, pub = nostr.keygen()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise KeyFileError(f"checkpoint key file {path}: exists; not replacing a key") from None
    except OSError as e:
        raise KeyFileError(f"checkpoint key file {path}: {e.strerror}") from None
    with os.fdopen(fd, "w", encoding="ascii") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(nostr.nsec(sec) + "\n")
    return nostr.npub(pub)


# ---------------------------------------------------------------- owed events

def _say(msg: str) -> None:
    print(f"aitools-alerts-poster: {msg}", file=sys.stderr)


def _entry_ok(o) -> bool:
    return (isinstance(o, dict) and set(o) == {"id", "bytes", "since", "root"} and nostr._is_hex(o["id"], 32)
            and type(o["bytes"]) is int and o["bytes"] >= 0 and type(o["since"]) is int
            and (o["root"] is None or nostr._is_hex(o["root"], 32)))


def load_owed(path) -> dict:
    """``{"last_seq": int, "owed": [{"id", "bytes", "since", "root"}]}``. A
    missing file is empty. A malformed one is also taken as empty, with a
    line on stderr: a lost number is made good from the published checkpoint
    or the clock, and lost owed ids are what a deleted file would lose too."""
    try:
        with open(path, "rb") as f:
            rec = json.loads(f.read(8 << 20).decode("utf-8"))
        ok = (isinstance(rec, dict) and set(rec) == {"last_seq", "owed"} and type(rec["last_seq"]) is int
              and 0 <= rec["last_seq"] <= cpt.MAX_SEQ and isinstance(rec["owed"], list)
              and all(_entry_ok(o) for o in rec["owed"]))
    except FileNotFoundError:
        return {"last_seq": 0, "owed": []}
    except (OSError, ValueError, RecursionError):
        ok = False
    if not ok:
        _say(f"checkpoint state {path} is unreadable; starting it again")
        return {"last_seq": 0, "owed": []}
    return rec


def save_owed(path, rec: dict) -> None:
    write_json(path, rec)


def record_sent(path, event_id, text_bytes: int, root, now: int) -> None:
    """Write down, at once, that the relay acknowledged ``event_id``: the
    poster owes it to every checkpoint until it has seen it on the mirror.
    Called from the send path, before the journal drops the item, so a run
    that then fails its pull or dies has still recorded it. ``root``: the
    thread root the post replied to, or None."""
    if not nostr._is_hex(event_id, 32):
        return
    rec = load_owed(path)
    if all(o["id"] != event_id for o in rec["owed"]):
        rec["owed"].append({"id": event_id, "bytes": int(text_bytes) + ENVELOPE, "since": int(now),
                            "root": root if nostr._is_hex(root, 32) else None})
        save_owed(path, rec)


def settle_owed(owed: list, present, now: int) -> tuple[list, int]:
    """The owed list after looking at the mirror, and how many entries were
    given up. An entry stays until its id is in ``present`` (the ids the
    poster now holds from the mirror); it is given up only after OWED_S.
    Nothing is dropped for lack of room: ``window`` refuses instead."""
    live = [o for o in owed if o["id"] not in present]
    kept = sorted((o for o in live if o["since"] > now - OWED_S), key=lambda o: (o["since"], o["id"]))
    return kept, len(live) - len(kept)


# ---------------------------------------------------------------- the window

def _size(ev: dict) -> int:
    """An event's bytes in a channel file, as the exporter measures them."""
    return len(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1


def window(events, m, owed: list, now: int, channels=None):
    """The ids one checkpoint lists, from ``events`` (the poster's verified
    copy of the mirror) and the owed entries, within MAX_LISTED events and
    MAX_LISTED_BYTES; or None when what MUST be listed does not fit, in which
    case no checkpoint may be signed.

    Must be listed, in this order: the owed ids; the root each owed reply
    names; and for every eligible thread its root and every curator reply (a
    curator reply is how an alert is retracted, lowered or corrected: no
    other traffic may push one out). Then whole threads, newest first; a
    thread that does not fit whole is skipped and the next is tried.

    Eligible: the thread's newest event is not older than the reader's
    retention less MARGIN_S. Events dated after ``now`` are never listed. A
    skipped thread whose listed events are all older than that line also has
    its newest event listed, so the reader's retention, which sees only
    listed events, keeps them."""
    channels = pull.channel_ids() if channels is None else channels
    usable = {ev["id"]: ev for ev in events if manifest.role_of(m, ev["pubkey"]) is not None
              and pull._bound(ev, channels) and ev["created_at"] <= now}
    threads: dict[str, list[dict]] = {}
    for ev in usable.values():
        threads.setdefault(pull._thread_ref(ev) or ev["id"], []).append(ev)
    cutoff = now - pull.RETENTION_S + MARGIN_S

    def newest(key):
        return max(threads[key], key=lambda e: (e["created_at"], e["id"]))
    order = sorted((k for k in threads if newest(k)["created_at"] >= cutoff),
                   key=lambda k: (newest(k)["created_at"], newest(k)["id"]), reverse=True)
    out: dict[str, None] = {}  # insertion-ordered set of ids
    used = {"n": 0, "bytes": 0}

    def take(ids_sizes) -> bool:
        fresh = list({i: b for i, b in ids_sizes if i not in out}.items())  # an id once, however often named
        if used["n"] + len(fresh) > MAX_LISTED or used["bytes"] + sum(b for _, b in fresh) > MAX_LISTED_BYTES:
            return False
        used["n"] += len(fresh)
        used["bytes"] += sum(b for _, b in fresh)
        out.update((i, None) for i, _ in fresh)
        return True

    def sized(evs):
        return [(e["id"], _size(e)) for e in evs]
    must = [(o["id"], o["bytes"]) for o in owed]
    must += sized(usable[o["root"]] for o in owed if o["root"] in usable)
    for key in order:
        must += sized(e for e in threads[key] if e["id"] == key
                      or manifest.role_of(m, e["pubkey"]) == "curator")
    if not take(must):
        return None
    for key in order:
        if take(sized(threads[key])):
            continue
        listed = [e for e in threads[key] if e["id"] in out]
        if listed and all(e["created_at"] < cutoff for e in listed):
            take(sized([newest(key)]))  # keeps the salvaged part inside the reader's retention
    return list(out)


def next_seq(now: int, last_seq: int, published_seq: int = 0) -> int:
    """The signing time in seconds, or one more than the highest number known
    to be used (this poster's last, and the published checkpoint's when this
    key signed it) when that is not lower: never a number twice, also within
    one second, and also after the poster's own count was lost."""
    return max(int(now), int(last_seq) + 1, int(published_seq) + 1)


# ---------------------------------------------------------------- one run

def run_checkpoint(config, now: int, *, ssh=None, fetch=None, root: str = TRUST_ROOT_PUBKEY) -> str:
    """Sign and deliver this run's checkpoint; returns the summary token:
    ``off`` (not configured), ``no-mirror`` (the pull failed), ``no-certificate``
    (no usable certificate names this key), ``too-large`` (what must be listed
    does not fit: nothing is signed), ``sent`` or ``failed``, with
    ``,owed_dropped=N`` appended when acknowledged posts were given up."""
    from aitools_alerts.poster import transport, translate
    if config.checkpoint_key_file is None or config.relay_put_wrapper is None:
        return "off"
    sec = read_key(config.checkpoint_key_file)
    pub = nostr.pubkey_gen(bytes.fromhex(sec)).hex()
    get = fetch or pull.default_fetch
    base = config.translate_mirror_url if config.translate_mirror_url.endswith("/") \
        else config.translate_mirror_url + "/"
    st = State.load(config.mirror_dir)
    try:
        res = translate.bounded(lambda: pull.fetch(base, st, fetch=fetch, root_pubkey=root, now=now,
                                                   checkpoint=False), 120)
    except (translate.CallError, ValueError, OSError):
        return "no-mirror"
    m = st.manifest
    if res.error is not None or m is None or st.manifest_root != root:
        return "no-mirror"
    cert = pull._choose_cert(m, root, now, None, [(get, base)])
    if cert is None or cpt.cert_problem(cert, m, now) is not None or cert.checkpoint_key != pub:
        return "no-certificate"
    published = 0
    try:  # the number of the checkpoint the mirror serves, when this key signed it: a floor for ours
        cp = cpt.load_checkpoint(get(base + "checkpoint.json"))
        if cpt.verify_checkpoint(cp, cert):
            published = cp.seq
    except Exception:  # noqa: BLE001 - none served, unreachable or malformed: no floor from it
        pass
    rec = load_owed(config.owed_state)
    owed, dropped = settle_owed(rec["owed"], set(st.events), now)
    tail = f",owed_dropped={dropped}" if dropped else ""
    ids = window(st.events.values(), m, owed, now)
    if ids is None:
        save_owed(config.owed_state, {"last_seq": rec["last_seq"], "owed": owed})
        _say(f"checkpoint not signed: {len(owed)} owed posts and the curator replies do not fit one checkpoint")
        return "too-large" + tail
    seq = next_seq(now, rec["last_seq"], published)
    save_owed(config.owed_state, {"last_seq": seq, "owed": owed})  # the number is used up before it is sent
    event = cpt.build_checkpoint(sec, m, seq, ids, int(now))
    del sec
    ok, detail = transport.put("checkpoint", json.dumps(event, separators=(",", ":")).encode("utf-8"), ssh,
                               host=config.relay_ssh_host, wrapper=config.relay_put_wrapper)
    if not ok:
        _say(f"checkpoint not delivered ({detail})")
    return ("sent" if ok else "failed") + tail
