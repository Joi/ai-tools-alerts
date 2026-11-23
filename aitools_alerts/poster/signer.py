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

__all__ = ["run_checkpoint", "KeyFileError", "read_key", "keygen", "init_owed", "load_owed", "save_owed", "record_sent", "settle_owed",
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


def init_owed(path) -> None:
    """Create the record for a new checkpoint key (checkpoint-keygen): nothing
    is owed and signing may start at once. Never replaces an existing one."""
    if not os.path.exists(path):
        save_owed(path, {"last_seq": 0, "owed": [], "hold_until": 0, "gone": {}})


def load_owed(path, now: int) -> dict:
    """``{"last_seq": int, "owed": [{"id", "bytes", "since", "root"}],
    "hold_until": int, "gone": {id: since}}``. ``gone``: events the poster
    holds that the mirror has stopped serving, and since when (settle_gone).

    The record is the only memory of what the relay acknowledged. If it is
    missing or unreadable, that memory is gone: the poster cannot know which
    posts it still owes, so it signs nothing for OWED_S (``hold_until``), the
    time after which any debt would have been given up anyway. Members read
    stale meanwhile, which is the truth. A new key starts with ``init_owed``
    and no hold."""
    try:
        with open(path, "rb") as f:
            rec = json.loads(f.read(8 << 20).decode("utf-8"))
        ok = (isinstance(rec, dict) and set(rec) == {"last_seq", "owed", "hold_until", "gone"}
              and type(rec["last_seq"]) is int and 0 <= rec["last_seq"] <= cpt.MAX_SEQ
              and type(rec["hold_until"]) is int and isinstance(rec["owed"], list)
              and all(_entry_ok(o) for o in rec["owed"]) and isinstance(rec["gone"], dict)
              and all(nostr._is_hex(k, 32) and type(v) is int for k, v in rec["gone"].items()))
    except FileNotFoundError:
        ok, why = False, "is missing"
    except (OSError, ValueError, RecursionError):
        ok, why = False, "is unreadable"
    else:
        why = "is malformed"
    if not ok:
        _say(f"checkpoint state {path} {why}: what the relay acknowledged is not known, "
             f"so no checkpoint is signed for {OWED_S // 3600} hours")
        return {"last_seq": 0, "owed": [], "hold_until": int(now) + OWED_S, "gone": {}}
    return rec


def save_owed(path, rec: dict) -> None:
    write_json(path, rec)


def record_sent(path, event_id, text_bytes: int, root, now: int) -> None:
    """Write down, at once, that the relay acknowledged ``event_id``: the
    poster owes it to every checkpoint until it has seen it on the mirror.
    Called from the send path, before the journal drops the item, so a run
    that then fails its pull or dies has still recorded it. ``root``: the
    thread root the post replied to, or None. Raises OSError when the record
    cannot be written: the caller must then not sign a checkpoint."""
    if not nostr._is_hex(event_id, 32):
        return
    rec = load_owed(path, now)
    if all(o["id"] != event_id for o in rec["owed"]):
        rec["owed"].append({"id": event_id, "bytes": int(text_bytes) + ENVELOPE, "since": int(now),
                            "root": root if nostr._is_hex(root, 32) else None})
    save_owed(path, rec)  # also when nothing was added: a hold that load_owed began must reach the disk


def settle_owed(owed: list, present, now: int) -> tuple[list, int]:
    """The owed list after looking at the mirror, and how many entries were
    given up. An entry stays until its id is in ``present`` (the ids the
    poster now holds from the mirror); it is given up only after OWED_S.
    Nothing is dropped for lack of room: ``window`` refuses instead."""
    live = [o for o in owed if o["id"] not in present]
    kept = sorted((o for o in live if o["since"] > now - OWED_S), key=lambda o: (o["since"], o["id"]))
    return kept, len(live) - len(kept)


def settle_gone(gone: dict, held, served, now: int) -> tuple[dict, set]:
    """Events the poster holds (``held``) that the mirror no longer serves
    (``served``: the ids in the channel files just fetched): since when each
    has been missing, and the ids to give up. The poster keeps listing a
    missing event, so readers refuse the mirror and read stale: that is how a
    relay that drops a post is noticed. After OWED_S it is given up (removed
    from the poster's copy), or a post that was truly deleted would keep
    every reader stale for as long as the poster remembers it."""
    missing = set(held) - set(served)
    since = {i: gone.get(i, int(now)) for i in missing}
    drop = {i for i, t in since.items() if t <= now - OWED_S}
    return {i: t for i, t in since.items() if i not in drop}, drop


# ---------------------------------------------------------------- the window

def _size(ev: dict) -> int:
    """An event's bytes in a channel file, as the exporter measures them."""
    return len(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1


def window(events, m, owed: list, now: int, channels=None):
    """The ids one checkpoint lists, from ``events`` (the poster's verified
    copy of the mirror) and the owed entries, within MAX_LISTED events and
    MAX_LISTED_BYTES; or None when what MUST be listed does not fit, in which
    case no checkpoint may be signed.

    Must be listed: the owed ids; and, for every eligible thread that has a
    curator reply or an owed reply, its root and every curator reply (a
    curator reply is how an alert is retracted, lowered or corrected: no
    other traffic may push one out). Then whole threads, newest first; a
    thread that does not fit whole is skipped and the next is tried. A plain
    root with no correction is not in the must-list: a year of daily digests
    must not by itself fill it.

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
    # A thread an owed reply belongs to is listed whatever its age: the owed
    # reply, once members have it, keeps the thread inside their retention, so
    # its root must come with every curator reply the poster knows.
    owed_roots = {o["root"] for o in owed if o["root"] in threads}
    order = sorted((k for k in threads if newest(k)["created_at"] >= cutoff or k in owed_roots),
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
    for key in order:
        fixes = [e for e in threads[key] if e["id"] != key and manifest.role_of(m, e["pubkey"]) == "curator"]
        if not fixes and key not in owed_roots:
            continue
        core = [e for e in threads[key] if e["id"] == key] + fixes
        if all(e["created_at"] < cutoff for e in core) and key not in owed_roots:
            # Root and corrections are all old, and only other replies keep the thread
            # alive: its newest event is listed with them, or the reader's retention,
            # which sees only listed events, would drop them.
            core.append(newest(key))
        must += sized(core)
    if not take(must):
        return None
    for key in order:
        take(sized(threads[key]))  # whole, or (too large) only what is already listed
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
    rec = load_owed(config.owed_state, now)
    if now < rec["hold_until"]:  # the record of what is owed was lost: see load_owed
        save_owed(config.owed_state, rec)
        return "held"
    sec = read_key(config.checkpoint_key_file)
    pub = nostr.pubkey_gen(bytes.fromhex(sec)).hex()
    get = fetch or pull.default_fetch
    base = config.translate_mirror_url if config.translate_mirror_url.endswith("/") \
        else config.translate_mirror_url + "/"
    st = State.load(config.mirror_dir)

    def read_mirror():
        """Everything read from the mirror, under one wall-clock bound: a mirror that
        drips bytes must not hold the run, and the ledger lock, past it."""
        seen = {}

        def keep(url, *a):
            seen[url.rsplit("/", 1)[1]] = body = get(url, *a)
            return body
        res = pull.fetch(base, st, fetch=keep, root_pubkey=root, now=now, checkpoint=False)
        docs = {name: seen.get(name) for name in pull.FILES}
        for name in ("checkpoint-key.json", "checkpoint.json"):
            try:
                docs[name] = get(base + name)
            except Exception:  # noqa: BLE001 - not served or unreachable: there is none
                docs[name] = None
        return res, docs
    try:
        res, docs = translate.bounded(read_mirror, 120)
    except (translate.CallError, ValueError, OSError):
        return "no-mirror"
    m = st.manifest
    if res.error is not None or m is None or st.manifest_root != root:
        return "no-mirror"

    def served(url):
        data = docs[url.rsplit("/", 1)[1]]
        if data is None:
            raise OSError("not served")
        return data
    cert = pull._choose_cert(m, root, now, None, [(served, base)])
    if cert is None or cpt.cert_problem(cert, m, now) is not None or cert.checkpoint_key != pub:
        return "no-certificate"
    published = 0
    try:  # the number of the checkpoint the mirror serves, when this key signed it: a floor for ours
        cp = cpt.load_checkpoint(served(base + "checkpoint.json"))
        if cpt.verify_checkpoint(cp, cert):
            published = cp.seq
    except (OSError, cpt.CheckpointError):  # none served or malformed: no floor from it
        pass
    # What the mirror serves right now (ids only; the pull verified what it stored).
    serving = set()
    for name in pull.FILES:
        try:
            serving |= {e["id"] for e in json.loads(docs[name])["events"] if isinstance(e.get("id"), str)}
        except (TypeError, ValueError, KeyError, AttributeError):
            return "no-mirror"
    gone, give_up = settle_gone(rec["gone"], st.events, serving, now)
    if give_up:  # missing for OWED_S: no longer the poster's to vouch for
        st.accept(root, m, {i: e for i, e in st.events.items() if i not in give_up})
        st.save_events()
    rec = {**rec, "gone": gone}
    # An acknowledged post stays owed until the poster holds it AND could list it: one
    # stamped after this run began is not listed yet, so it is not settled yet either.
    owed, dropped = settle_owed(rec["owed"], {i for i, e in st.events.items() if e["created_at"] <= now}, now)
    tail = (f",owed_dropped={dropped}" if dropped else "") + (f",gone_dropped={len(give_up)}" if give_up else "")
    ids = window(st.events.values(), m, owed, now)
    if ids is None:
        save_owed(config.owed_state, {**rec, "owed": owed})
        _say(f"checkpoint not signed: {len(owed)} owed posts and the curator replies do not fit one checkpoint")
        return "too-large" + tail
    seq = next_seq(now, rec["last_seq"], published)
    save_owed(config.owed_state, {**rec, "last_seq": seq, "owed": owed})  # the number is used up before it is sent
    event = cpt.build_checkpoint(sec, m, seq, ids, int(now))
    del sec
    ok, detail = transport.put("checkpoint", json.dumps(event, separators=(",", ":")).encode("utf-8"), ssh,
                               host=config.relay_ssh_host, wrapper=config.relay_put_wrapper)
    if not ok:
        _say(f"checkpoint not delivered ({detail})")
    return ("sent" if ok else "failed") + tail
