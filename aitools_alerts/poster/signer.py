"""Sign the feed checkpoint on the poster machine (ai-tools-alerts#nfm3).

The checkpoint (``aitools_alerts.checkpoint``) lists the events that exist,
so that the mirror, which the relay VM serves, cannot leave one out
unnoticed. It is signed here, with a key that never reaches that VM, at the
end of every poster run, and delivered over the poster's ssh route to a
command that only stores it; the exporter verifies it before publishing.

What it vouches for: every event in the poster's verified copy of the
mirror inside the window, and every event this poster sent and the relay
acknowledged (``owed``) until the poster has seen it on the mirror. A
thread whose root carries a claim decays on readers unless it is renewed
(ai-tools-alerts#gtw9), so its root is never listed without the renewals
that keep it standing: see ``renewals_of``, ``settle_gone``, ``settle_owed``
and ``window``. It does not vouch for a curator's post the relay withheld before the poster ever saw
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

__all__ = ["run_checkpoint", "KeyFileError", "read_key", "keygen", "init_owed", "load_owed", "save_owed", "record_sent", "settle_owed", "renewals_of", "lapsed",
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


def _times_ok(v) -> bool:
    return isinstance(v, list) and len(v) == 2 and all(type(t) is int for t in v)


def _entry_ok(o) -> bool:
    return (isinstance(o, dict) and set(o) - {"renewal"} == {"id", "bytes", "since", "root"} and nostr._is_hex(o["id"], 32)
            and type(o["bytes"]) is int and o["bytes"] >= 0 and type(o["since"]) is int
            and (o["root"] is None or nostr._is_hex(o["root"], 32))
            and ("renewal" not in o or (_times_ok(o["renewal"]) and o["root"] is not None)))


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


def record_sent(path, event_id, text_bytes: int, root, now: int, renewal=None) -> None:
    """Write down, at once, that the relay acknowledged ``event_id``: the
    poster owes it to every checkpoint until it has seen it on the mirror.
    Called from the send path, before the journal drops the item, so a run
    that then fails its pull or dies has still recorded it. ``root``: the
    thread root the post replied to, or None. ``renewal``: the
    (confirmed_at, checked_at) of the claim a reply carries when a reader
    takes it as a renewal of that thread (gtw9), else None. Raises OSError
    when the record cannot be written: the caller must then not sign a
    checkpoint."""
    if not nostr._is_hex(event_id, 32):
        return
    rec = load_owed(path, now)
    if all(o["id"] != event_id for o in rec["owed"]):
        root = root if nostr._is_hex(root, 32) else None
        rec["owed"].append({"id": event_id, "bytes": int(text_bytes) + ENVELOPE, "since": int(now), "root": root,
                            **({"renewal": [int(t) for t in renewal]} if renewal and root else {})})
    save_owed(path, rec)  # also when nothing was added: a hold that load_owed began must reach the disk


def renewals_of(ev: dict, m) -> list:
    """The (confirmed_at, checked_at) pairs a reader counts as renewals of its
    thread for one relay-bot reply (gtw9): its claim's, when the claim is well
    formed, of a level and checked no later than the event is dated
    (``pull._renewal``); and the event's own date twice when its block names a
    level (``pull.threads_from``). Empty for any other event."""
    if pull._thread_ref(ev) is None or manifest.role_of(m, ev["pubkey"]) != "relay-bot":
        return []
    rn = pull._renewal(ev, "relay-bot")
    out = [] if rn is None else [(rn[1], rn[2])]
    named = (pull._patch(ev["content"]) or {}).get("level")
    if isinstance(named, str) and named in pull._RANK:
        out.append((ev["created_at"], ev["created_at"]))
    return out


def _later(events, m) -> dict:
    """Thread root -> every renewal pair its replies among ``events`` carry."""
    out: dict[str, list] = {}
    for ev in events:
        for pair in renewals_of(ev, m):
            out.setdefault(pull._thread_ref(ev), []).append(pair)
    return out


def _redundant(pairs, root, later: dict) -> bool:
    """Each of ``pairs`` is matched by a renewal of the thread in ``later`` that
    confirms and checks no earlier: a reader that lacks them loses nothing."""
    return all(any(c >= p[0] and k >= p[1] for c, k in later.get(root, ())) for p in pairs)


def _frontier(replies, m) -> list:
    """The replies of one thread that carry a renewal no other of them makes
    redundant: what a checkpoint must list with the root (one event per pair)."""
    first: dict[tuple, dict] = {}
    for ev in sorted(replies, key=lambda e: e["id"]):
        for pair in renewals_of(ev, m):
            first.setdefault(pair, ev)
    top = [p for p in first if not any(q != p and q[0] >= p[0] and q[1] >= p[1] for q in first)]
    return list({first[p]["id"]: first[p] for p in top}.values())


def lapsed(events, m, now: int, channels=None) -> set:
    """The roots, among ``events``, of threads a reader of exactly these events
    would decay at ``now`` although the poster never said so (gtw9). The
    threads are built and taken as they stand by the reader's own code
    (``pull.threads_from``, ``pull.standing``), so what counts as a renewal (a
    claim that names an id the thread has held, a level reply the reader
    accepts), and whether a curator's hold is in force, are the reader's
    answers. A thread is lapsed when it can decay (its root carries a claim,
    no hold, not retracted) and its renewals no longer keep standing the level
    the bot last published: the reader's level, or the lower one the bot has
    offered since. They are left out of the checkpoint, whatever the reason
    the renewal or the level reply is not there: a send that failed, a channel
    one reply never reached, a lost ledger or state file, a mirror that hid
    it. A thread the checkpoint does not list keeps its level on a reader. At
    notice the thread is listed and leaves readers: that is the one decay the
    poster intends (it posts every step above it before the level's life
    ends). Raises when the ruleset cannot be loaded: readers with a sound one
    would expire what this could not judge, so nothing is signed."""
    from aitools_alerts import ruleset
    channels = pull.channel_ids() if channels is None else channels
    rs = ruleset.load()
    usable = [ev for ev in events if manifest.role_of(m, ev["pubkey"]) is not None
              and pull._bound(ev, channels) and ev["created_at"] <= now]
    out = set()
    for t in pull.threads_from(usable, m):
        t = pull.standing(t, now)
        if t.retracted or t.enrolled_at is None or t.curated or t.adv.expires_at is not None:
            continue
        level = t.adv.level
        if t.offered in pull._RANK and pull._RANK[t.offered] < pull._RANK[level]:
            level = t.offered
        if level != rs.levels[0] and rs.level_at(level, [(c, k) for c, k, _ in t.renewals], now) != level:
            out.add(t.root_id)
    return out


def settle_owed(owed: list, present, now: int, later: dict | None = None) -> tuple[list, int, set]:
    """The owed list after looking at the mirror, how many entries were
    given up, and the thread roots to leave out of checkpoints. An entry
    stays until its id is in ``present`` (the ids the poster now holds from
    the mirror); it is given up only after OWED_S. Nothing is dropped for
    lack of room: ``window`` refuses instead.

    A renewal (an entry with ``renewal``) is not given up at OWED_S (gtw9):
    a checkpoint that lists the root without it would let every reader decay
    the alert, which is what a mirror hiding it wants. It stays owed, off the
    must-list, and its thread is left out of checkpoints (``suppress``) until
    the poster holds it or a renewal of the thread that makes it redundant
    (``later``: ``_later`` of the poster's copy)."""
    later = later or {}
    live = [o for o in owed if o["id"] not in present
            and not ("renewal" in o and _redundant([o["renewal"]], o["root"], later))]
    late = [o for o in live if o["since"] <= now - OWED_S]
    kept = sorted((o for o in live if o not in late or "renewal" in o), key=lambda o: (o["since"], o["id"]))
    return kept, len(late) - sum("renewal" in o for o in late), {o["root"] for o in late if "renewal" in o}


def settle_gone(gone: dict, held: dict, served, now: int, m) -> tuple[dict, set, set]:
    """Events the poster holds (``held``, id -> event) that the mirror no
    longer serves (``served``: ids of the validly signed events in the channel
    files just fetched): (since when each has been missing, the ids to give
    up, the thread roots to leave out of checkpoints).

    The poster keeps listing a missing event, so readers refuse the mirror and
    read stale: that is how a relay that drops a post is noticed. After OWED_S
    it must end, or a post that was truly deleted would keep every reader
    stale for as long as the poster remembers it. How it ends depends on what
    is missing. A root or an ordinary reply is given up: removed from the
    poster's copy. A curator reply is never given up, because a checkpoint
    with the root and without that reply would certify the alert as it stood
    before the correction, a retracted alert as live. Its whole thread is
    left out of checkpoints instead, for as long as the reply is missing:
    new members do not see the thread; members who hold the correction keep it.
    So is the thread of a relay-bot renewal (``renewals_of``, gtw9), in a
    thread whose root carries a claim, that no served renewal makes redundant: listed without it, the alert would decay
    on every reader. Once a later renewal is served it is given up like any reply."""
    missing = set(held) - set(served)
    since = {i: gone.get(i, int(now)) for i in missing}
    late = {i for i, t in since.items() if t <= now - OWED_S}
    later = _later((held[i] for i in held if i in served), m)

    def enrolled(root) -> bool:  # its root carries a claim: readers compute its life (pull.threads_from)
        ev = held.get(root)  # a root given up for missing may come back: its renewals are kept for it
        return ev is None or (manifest.role_of(m, ev["pubkey"]) == "relay-bot"
                              and pull._renewal(ev, "relay-bot") is not None)
    fixes = {i for i in late if pull._thread_ref(held[i]) is not None
             and (manifest.role_of(m, held[i]["pubkey"]) == "curator"
                  or (enrolled(pull._thread_ref(held[i])) and (rn := renewals_of(held[i], m))
                      and not _redundant(rn, pull._thread_ref(held[i]), later)))}
    drop = late - fixes
    suppress = {pull._thread_ref(held[i]) for i in fixes}
    return {i: t for i, t in since.items() if i not in drop}, drop, suppress


# ---------------------------------------------------------------- the window

def _size(ev: dict) -> int:
    """An event's bytes in a channel file, as the exporter measures them."""
    return len(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 1


def window(events, m, owed: list, now: int, channels=None, suppress=frozenset()):
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
    listed events, keeps them. ``suppress``: thread roots to leave out whole
    (see settle_gone)."""
    channels = pull.channel_ids() if channels is None else channels
    usable = {ev["id"]: ev for ev in events if manifest.role_of(m, ev["pubkey"]) is not None
              and pull._bound(ev, channels) and ev["created_at"] <= now}
    threads: dict[str, list[dict]] = {}
    for ev in usable.values():
        key = pull._thread_ref(ev) or ev["id"]
        if key not in suppress:
            threads.setdefault(key, []).append(ev)
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
        # gtw9: and the renewals that keep it standing. A root listed without them (the
        # thread does not fit whole) would decay on a reader that the mirror serves in full.
        core += [e for e in _frontier([e for e in threads[key] if e["id"] != key], m) if e not in core]
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

def run_checkpoint(config, now: int, *, ssh=None, fetch=None, root: str = TRUST_ROOT_PUBKEY,
                   suppress=frozenset()) -> str:
    """Sign and deliver this run's checkpoint; returns the summary token:
    ``off`` (not configured), ``no-mirror`` (the pull failed), ``no-certificate``
    (no usable certificate names this key), ``too-large`` (what must be listed
    does not fit: nothing is signed), ``sent`` or ``failed``, with
    ``,owed_dropped=N`` appended when acknowledged posts were given up.
    ``suppress``: thread roots the caller will not vouch for in this checkpoint
    (gtw9: a renewal that was due could not be delivered)."""
    from aitools_alerts.poster import transport, translate
    if config.checkpoint_key_file is None or config.relay_put_wrapper is None or config.relay_ssh_host is None:
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
    # What the mirror serves right now: the events in the fetched files whose own signature
    # verifies. The stored copy is no evidence (the pull keeps a stored event when the mirror
    # sends a broken copy of it), and a bare id is not an event a reader could take.
    serving = set()
    for name in pull.FILES:
        try:
            serving |= {e["id"] for e in json.loads(docs[name])["events"] if nostr.verify_event(e)}
        except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
            return "no-mirror"
    gone, give_up, hidden_gone = settle_gone(rec["gone"], st.events, serving, now, m)
    suppress = set(suppress) | hidden_gone
    if give_up:  # missing for OWED_S: no longer the poster's to vouch for
        st.accept(root, m, {i: e for i, e in st.events.items() if i not in give_up})
        st.save_events()
    rec = {**rec, "gone": gone}
    # An acknowledged post stays owed until the poster holds it AND could list it: one
    # stamped after this run began is not listed yet, so it is not settled yet either.
    # gtw9: a renewal neither the mirror nor a later renewal has replaced keeps its thread out.
    owed, dropped, hidden = settle_owed(rec["owed"], {i for i, e in st.events.items() if e["created_at"] <= now}, now,
                                        _later((e for e in st.events.values() if e["created_at"] <= now), m))
    suppress = suppress | hidden
    listable = [o for o in owed if not ("renewal" in o and o["since"] <= now - OWED_S)]
    # gtw9: and no root a reader of the poster's own copy would decay unasked (``lapsed``).
    suppress = suppress | lapsed(st.events.values(), m, now)
    tail = ((f",owed_dropped={dropped}" if dropped else "") + (f",gone_dropped={len(give_up)}" if give_up else "")
            + (f",threads_suppressed={len(suppress)}" if suppress else ""))
    ids = window(st.events.values(), m, listable, now, suppress=suppress)
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
