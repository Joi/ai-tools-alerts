"""Fetch the signed mirror, decide which events to believe, build advisories.

Verification order, every pull: the manifest is signed by the trust root and
is not older than the one already accepted (or the bundled one); then each
event's signature; then the event's key must be in the CURRENT manifest; the
post block is parsed last, when advisories are built. ``posted_by`` always
comes from the manifest role of the event's key, never from the block.

A pull that fails anywhere before the save changes no event, manifest or
seen record: a truncated or half-written mirror file is "mirror unreadable",
never an empty feed. Stored events are re-checked against the current
manifest on every pull, so a key removed from the manifest loses its events,
its retractions included; a retraction that must outlive its signer's key is
listed in the manifest's ``retracted`` (see ``advisories``).

Relay deletions (kind 9005, by a relay admin or by a root's own author) and
NIP-09 deletions (kind 5) are not read, whoever signed them. Readers trust signed posters, not relay admin events: the stored
events and the manifest floor stand, and a thread is withdrawn only by a
trusted curator's retraction or by the manifest's ``retracted`` list. A
curator's retraction of a relay-bot thread is held 14 days and checked by
the member's own source check, like every curator action on such a thread
(ai-tools-alerts#c1g2: ``threads_from``, ``standing``).

An event counts only when it is a kind 9 message carrying one ``h`` tag that
names a channel in spec/channels.json (``_bound``): a signature a poster's key
made anywhere else is never an alert, a patch or a retraction. An event not
yet stored and dated more than MAX_AHEAD_S after the reader's clock is
refused. A stored event is never re-judged by its date: a clock set back must
not undo a stored retraction. It only leaves the stale check while ahead.

Each event is signed; the set is not, so a member pull also needs the signed
checkpoint (``checkpoint``): a certificate from the trust root naming the
checkpoint key, and a checkpoint from that key listing the events that exist.
A new event is admitted only when an accepted checkpoint lists it; a pull
whose mirror lacks a listed event is refused; a certificate or checkpoint
older than the accepted one is refused; an event once applied stays applied
while it is stored, so no checkpoint can take a retraction away. Only applied
events are stored (events.json holds nothing the released reader, run on the
same state, should not show). The manifest
and the certificate are also fetched from a second origin, and the higher
manifest wins. ``unverified`` says whether what the reader shows may be
trusted to be complete right now; the CLI auto-applies nothing when it may
not. The poster and the curator command, which write the feed, pull with
``checkpoint=False``: every verified event, as before, never a verified state.

Expiry (ai-tools-alerts#r0ra) is computed, and judged by the checkpoint, never
by this machine's clock: see ``active``. A relay-bot block's ``expires_at`` is
not read. A thread whose root carries a claim stands for as long as its
claims keep a level standing (``ruleset.Ruleset.level_at``), and it decays
only under a stored checkpoint issued after that which lists its root and
has reached the date of each of its claims. A
frozen mirror, a withheld renewal or a wrong clock therefore expire nothing;
retention takes its clock from the checkpoint too (``_fetch``).
"""

from __future__ import annotations

import copy
import hashlib
import http.client
import json
import re
import time
import unicodedata
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from urllib.parse import urlsplit

from . import TRUST_DIR, TRUST_ROOT_PUBKEY, manifest, nostr, ruleset, schema, versions, wire
from . import checkpoint as cpt
from .manifest import Manifest
from .schema import Advisory
from .state import EVENT_KEYS, State

__all__ = ["FILES", "FetchError", "PULL_ERRORS", "MAX_FETCH_BYTES", "MAX_EVENTS", "PullResult", "Thread",
           "fetch", "default_fetch", "advisories", "active", "bundled_manifest",
           "parse_translation", "translation_title", "threads_from",
           "STALE_EVENT_S", "STALE_MANIFEST_S", "freshness", "stale_since",
           "MAX_AHEAD_S", "CHAT_KIND", "ChannelSpecError", "channel_ids", "unverified",
           "bundled_cert", "SECOND_TIMEOUT", "head_clock", "CURATOR_HOLD_S", "NONE", "standing", "asks",
           "widest", "UNCHECKED_LOWERING_S", "offers", "narrow_key"]

FILES = ("feed.json", "critical.json")
MAX_FETCH_BYTES = 8 << 20
MAX_EVENTS = 10000
MAX_STORED_EVENTS = 20000
MAX_STORED_BYTES = 32 << 20  # serialized, all roots; half state.MAX_STATE_BYTES
RETENTION_S = 400 * 86400
STALE_EVENT_S = 3 * 86400  # kept for importers; freshness is the checkpoint's validity now
STALE_MANIFEST_S = 90 * 86400
MAX_AHEAD_S = 600  # an event dated further ahead of the local clock is not admitted
CHAT_KIND = 9  # NIP-29 group chat message: the only kind posters and curators send
CHANNEL_NAMES = ("feed", "critical")  # the keys of spec/channels.json, exactly
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
TIMEOUT = 20
SECOND_TIMEOUT = 5  # the second origin must not hold up a session-start hook
_RANK = {"notice": 1, "high": 2, "critical": 3}
CURATOR_HOLD_S = 14 * 86400  # c1g2: a curator's word on a relay-bot thread holds this long unchecked
NONE = ruleset.NONE  # the level a retraction publishes
# tavj: a relay-bot lowering this machine's check cannot settle applies once checkpoints
# this far apart have listed it
UNCHECKED_LOWERING_S = 72 * 3600
_PATCH_KEYS = frozenset(f for f in Advisory.__dataclass_fields__)
_DELETION_KINDS = frozenset({5, 9005})  # NIP-09 deletion, NIP-29 relay delete-event
MAX_TRANSLATION_CHARS = 8000
_LANG = re.compile(r"lang:\s*([a-z]{2,8})")
_OF = re.compile(r"of:\s*([0-9a-f]{64})")


@dataclass
class PullResult:
    new_events: list = field(default_factory=list)
    dropped: Counter = field(default_factory=Counter)
    manifest: Manifest | None = None
    error: str | None = None


@dataclass(frozen=True)
class Thread:
    root_id: str
    adv: Advisory
    retracted: bool
    updated_at: int
    translations: dict = field(default_factory=dict)  # lang -> text of the current advisory
    translated_at: dict = field(default_factory=dict)  # lang -> created_at of that reply
    # What ``active`` computes expiry from (see _renewal): each (confirmed_at, checked_at,
    # the event's created_at), and one for each relay-bot reply that names a level. ``enrolled_at``:
    # the root's created_at when the root itself carries a claim, else None; only then
    # can the thread decay. ``curated``: a curator posted it, or a curator's hold on it is
    # in force (c1g2); it does not decay.
    renewals: tuple = ()
    enrolled_at: int | None = None
    curated: bool = False
    # c1g2, a relay-bot thread only (None, None, None, () for a curator's own thread and for
    # one the manifest retracts). ``wide``: the widest state, every reply under the relay
    # bot's rules. ``held_until``: a curator's word (``adv``, ``retracted``) holds until then.
    # ``offered``: the level last published below ``wide``'s, "none" for a retraction; replay
    # never applies it. ``held_aliases``: every alias ``wide`` has held. ``held_fixed``:
    # ((ecosystem, product name), the first fixed version it stated). ``refused``: set by ``standing``
    # when the member's check contradicted a lowering: the level left unapplied.
    wide: Advisory | None = None
    held_until: int | None = None
    offered: str | None = None
    held_aliases: tuple = ()
    held_fixed: tuple = ()
    held_products: tuple = ()  # entries whose exact product (ecosystem and name) ``wide`` no longer carries
    refused: str | None = None
    # tavj, a relay-bot thread only. ``offered_by``: the id of the relay-bot reply that
    # published ``offered`` (the first of them when the same level was offered again);
    # None when a curator offered it. ``stated``: (level, the event's claim or None) for the
    # root and for every reply that names a level, a curator's with None: what tells a level
    # that rests on fields from one that may rest on a reading (``verify.claimed``).
    # ``waiting``: set by ``standing``: the relay-bot lowering the check could not settle and
    # that has not yet stood UNCHECKED_LOWERING_S.
    offered_by: str | None = None
    stated: tuple = ()
    waiting: str | None = None
    # swfe, a relay-bot thread only. ``narrowed``: the products list last published that does
    # not stand for every entry of ``wide``'s (the join never applies it); None: none.
    # ``narrowed_by``: the id of the relay-bot reply that published it (the first of them
    # when the same list was sent again). ``narrowings``: ``narrow_key`` of every such list
    # the thread has published, the ended ones too: what a member's memory of refused
    # lists is kept against. Set by ``standing``: ``narrow_refused``, the member's check
    # contradicted it; ``narrow_waiting``, the check could not settle it and it has not
    # yet stood UNCHECKED_LOWERING_S.
    narrowed: tuple | None = None
    narrowed_by: str | None = None
    narrowings: tuple = ()
    narrow_refused: bool = False
    narrow_waiting: bool = False


# ------------------------------------------------------------------ fetching

# PullResult.error is None, "http <status>" or one of these: never server text.
PULL_ERRORS = ("timeout", "unreachable", "too large", "bad manifest", "bad event file",
               "manifest not signed by the trust root", "state limit reached: new events not stored",
               "bad channel spec", "interrupted", "no checkpoint key certificate", "no checkpoint",
               "bad checkpoint", "checkpoint dated ahead of this clock", "older checkpoint",
               "conflicting checkpoint", "mirror incomplete")


class ChannelSpecError(ValueError):
    """spec/channels.json is missing or malformed: no event can be bound to a channel."""


def channel_ids() -> frozenset:
    """The ids of the alert channels, from the packaged spec/channels.json."""
    try:
        obj = json.loads((schema.SPEC_DIR / "channels.json").read_text(encoding="utf-8"),
                         object_pairs_hook=schema._no_duplicates, parse_constant=schema._reject_constant)
    except (OSError, ValueError, RecursionError):
        raise ChannelSpecError("spec/channels.json is unreadable; reinstall aitools-alerts") from None
    # Exactly the two channels, distinct: a file naming one would silently drop the
    # other's alerts and retractions, and an extra entry would admit a third channel.
    if (not isinstance(obj, dict) or set(obj) != set(CHANNEL_NAMES)
            or not all(isinstance(v, str) and _UUID.fullmatch(v) for v in obj.values())
            or len(set(obj.values())) != len(CHANNEL_NAMES)):
        raise ChannelSpecError("spec/channels.json does not name the alert channels; reinstall aitools-alerts")
    return frozenset(obj.values())


def _bound(ev: dict, channels) -> bool:
    """A kind 9 event with exactly one h tag, naming an alert channel."""
    if ev.get("kind") != CHAT_KIND or not isinstance(ev.get("tags"), list):
        return False
    h = [t for t in ev["tags"] if isinstance(t, list) and t and t[0] == "h"]
    return len(h) == 1 and len(h[0]) >= 2 and h[0][1] in channels


class FetchError(OSError):
    """A fetch failure whose text is "http <status>" or a PULL_ERRORS string."""


def _kind(e: Exception) -> str:
    if isinstance(e, FetchError):  # checked: an injected fetcher's FetchError is not trusted
        return str(e) if str(e) in PULL_ERRORS or re.fullmatch(r"http [1-5][0-9][0-9]", str(e)) else "unreachable"
    return "timeout" if isinstance(e, TimeoutError) else "unreachable"


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError(f"refused redirect to {urlsplit(newurl).scheme or 'a relative'} URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirect)


def default_fetch(url: str, timeout: float = TIMEOUT) -> bytes:
    """GET an https:// or file:// URL; at most MAX_FETCH_BYTES. Raises OSError."""
    scheme = urlsplit(url).scheme
    if scheme not in ("https", "file"):
        raise FetchError("unreachable")
    req = urllib.request.Request(url, headers={"User-Agent": "aitools-alerts"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            data = r.read(MAX_FETCH_BYTES + 1)
    except urllib.error.HTTPError as e:
        e.close()
        raise FetchError(_kind(FetchError(f"http {e.code}"))) from None
    except urllib.error.URLError as e:
        raise FetchError(_kind(e.reason if isinstance(e.reason, Exception) else e)) from None
    except (TimeoutError, OSError, ValueError, http.client.HTTPException) as e:  # a read timeout, a reset, a malformed URL
        raise FetchError(_kind(e)) from None
    if len(data) > MAX_FETCH_BYTES:
        raise FetchError("too large")
    return data


def bundled_manifest() -> Manifest | None:
    """The manifest shipped in trust/, if it verifies under the pinned root."""
    try:
        m = manifest.load(TRUST_DIR / "manifest.json")
    except manifest.ManifestError:
        return None
    return m if manifest.verify(m, TRUST_ROOT_PUBKEY) else None


def bundled_cert():
    """The checkpoint key certificate shipped in trust/, if there is one and
    it verifies under the pinned root."""
    try:
        c = cpt.load_cert(TRUST_DIR / "checkpoint-key.json")
    except cpt.CheckpointError:
        return None
    return c if cpt.verify_cert(c, TRUST_ROOT_PUBKEY) else None


def _floor(state: State, root: str) -> Manifest | None:
    cands = [state.accepted(root)] if state.accepted(root) is not None else []
    if root == TRUST_ROOT_PUBKEY:
        b = bundled_manifest()
        if b is not None:
            cands.append(b)
    return max(cands, key=lambda m: m.version, default=None)


def _events_file(data: bytes, name: str) -> list:
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=schema._no_duplicates,
                         parse_constant=schema._reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise ValueError(f"{name}: not JSON ({e})") from None
    if (not isinstance(obj, dict) or not isinstance(obj.get("generated_at"), str)
            or not isinstance(obj.get("channel"), str) or not isinstance(obj.get("events"), list)):
        raise ValueError(f"{name}: needs generated_at, channel and an events list")
    if len(obj["events"]) > MAX_EVENTS:
        raise ValueError(f"{name}: more than {MAX_EVENTS} events")
    return obj["events"]


def fetch(base_url: str, state: State, fetch=None, root_pubkey: str = TRUST_ROOT_PUBKEY,
          now: float | None = None, second_origin: str | None = None,
          checkpoint: bool = True) -> PullResult:
    """Pull the mirror at ``base_url`` into ``state`` under the state lock.

    ``second_origin``: a URL prefix ending in "/" that also serves
    manifest.json and checkpoint-key.json (another operator than the mirror);
    None skips it. ``checkpoint=False`` is the pull of the feed's writers (the
    poster, the curator command): every verified event is stored, no
    checkpoint is asked for, and the pull never counts as a checked one."""
    get2 = fetch or (lambda url: default_fetch(url, SECOND_TIMEOUT))
    with state.locked():
        return _fetch(base_url, state, fetch or default_fetch, root_pubkey,
                      time.time() if now is None else now, second_origin, get2, checkpoint)


def _filter(stored: dict, fetched: list, m: Manifest, floor: Manifest | None,
            res: PullResult, channels, now: float) -> dict:
    """Events whose key is in ``m``: the stored ones (verified when they were
    stored), then each fetched one that verifies. A fetched event is verified
    before it can claim its id, so a forged copy of a genuine id never
    displaces the genuine one. Only the seven NIP-01 fields are kept: an
    unsigned extra field never reaches state. An event not bound to an alert
    channel is dropped, stored or fetched; one dated more than MAX_AHEAD_S
    ahead is dropped only when it is not stored yet (see the module text)."""
    kept: dict[str, dict] = {}
    why: dict[str, str] = {}  # id -> reason, counted once per id
    for ev, verified in [(e, True) for e in stored.values()] + [(e, False) for e in fetched]:
        if not isinstance(ev, dict) or not isinstance(ev.get("id"), str):
            res.dropped["malformed"] += 1
            continue
        eid = ev["id"]
        if eid in kept:
            continue  # the same event served twice (feed and critical)
        if not verified and not nostr.verify_event(ev):
            why.setdefault(eid, "bad-signature")
        elif manifest.role_of(m, ev["pubkey"]) is None:
            was = verified or (floor is not None
                               and manifest.role_of(floor, ev["pubkey"]) is not None)
            why.setdefault(eid, "revoked" if was else "unknown-poster")
        elif not _bound(ev, channels):
            why.setdefault(eid, "not-channel-post")
        elif not verified and ev["created_at"] > now + MAX_AHEAD_S:
            why.setdefault(eid, "future-dated")
        else:
            kept[eid] = {k: copy.deepcopy(ev[k]) for k in EVENT_KEYS}
            why.pop(eid, None)
    res.dropped.update(why.values())
    return kept


def _retain(kept: dict, now: float, res: PullResult) -> dict:
    """Drop whole threads (a root and every reply to it) whose newest event
    is older than RETENTION_S. A thread is kept or dropped as a unit, so a
    retraction, a patch or a curator amendment never outlives or predeceases
    its thread. A checkpoint that lists an aged-out thread does not bring it
    back. ``now`` is the caller's retention clock: a checked pull passes the
    checkpoint's time when that is earlier than this machine's clock, so a
    clock set ahead ages nothing out."""
    cutoff = now - RETENTION_S
    newest: dict[str, int] = {}
    for eid, ev in kept.items():
        key = _thread_ref(ev) or eid
        newest[key] = max(newest.get(key, 0), ev["created_at"])
    out = {eid: ev for eid, ev in kept.items() if newest[_thread_ref(ev) or eid] >= cutoff}
    if len(out) < len(kept):
        res.dropped["aged-out"] += len(kept) - len(out)
    return out


def _fetch(base_url, state: State, get, root_pubkey: str, now: float, second: str | None,
           get2, check: bool) -> PullResult:
    base = base_url if base_url.endswith("/") else base_url + "/"
    floor = _floor(state, root_pubkey)
    res = PullResult(manifest=state.accepted(root_pubkey) or floor)
    before = state.events_for(root_pubkey)
    channels = None
    extra: dict = {"second_origin": None}
    rnow = now  # the retention clock; a checked pull that holds a checkpoint sets it below

    def record(ok: bool, error: str | None) -> None:
        last = {"at": int(now), "mirror_url": base, "ok": ok, "error": error,
                "last_ok_at": int(now) if ok else state.last_pull.get("last_ok_at"),
                # True only for a checked pull that finished: what ``unverified`` reads
                "checkpoint_ok": bool(ok and check),
                # this pull stored events without a checkpoint: the next checked pull keeps them applied
                "writer": not check}
        last.update(extra)
        if ok:
            last.update(new=len(res.new_events), dropped=dict(res.dropped))
        same_root = state.manifest_root == root_pubkey  # else the times are another root's
        last.update(zip(("newest_event_at", "manifest_issued_at"),
                        freshness(state, now, channels) if same_root and channels else (None, None)))
        state.last_pull = last

    def fail(msg: str) -> PullResult:
        res.error = msg
        record(False, msg)
        state.save_last_pull()
        return res

    # What the reader held applied before this pull. If the last pull was made
    # by a reader that knows no checkpoint (the released one, run on this state
    # directory: last_pull has no checkpoint_ok) or was a writer's pull (the
    # curator command on this machine), everything it stored joins the applied
    # set now and is saved before step 0 stamps last_pull: a retraction that
    # pull fetched must not be un-applied by the next member pull. Only a
    # machine whose owner ran such a pull is affected, and it reads unverified
    # until a checked pull succeeds.
    t = state.trust.get(root_pubkey)
    old_cert = t["cert"] if t else None
    old_cp = t["checkpoint"] if t else None
    old_applied = set(t["applied"]) if t and old_cp is not None else None
    if check and old_cp is not None:
        rnow = min(now, old_cp.created_at)
    unchecked = "checkpoint_ok" not in state.last_pull or state.last_pull.get("writer") is True
    if unchecked:
        # last_pull is one record for every trust root, and step 0 is about to
        # overwrite it: merge for each root that holds a checkpoint, not only
        # the one this pull is for.
        merged = False
        for r, tr in state.trust.items():
            if tr["checkpoint"] is not None and not set(state.events_for(r)) <= tr["applied"]:
                tr["applied"] |= set(state.events_for(r))
                merged = True
        if merged:
            state.save_trust()
        if old_applied is not None:
            old_applied = set(state.trust[root_pubkey]["applied"])
    # 0. The pull has begun and nothing is verified yet. Written before any
    # fetch, in every mode, so a crash, or a failed write of the final record,
    # never leaves an earlier pull's success standing.
    state.last_pull = {**state.last_pull, "at": int(now), "mirror_url": base, "ok": False,
                       "error": "interrupted", "checkpoint_ok": False,
                       "writer": (not check) or (unchecked and bool(before))}
    state.save_last_pull()
    try:
        channels = channel_ids()
    except ChannelSpecError:
        return fail("bad channel spec")
    # 1. manifest: from the mirror and the second origin; each well formed, not
    # older than the floor, signed by the trust root. The higher version wins;
    # at equal versions the second origin's (the repository is the source).
    # The second origin is asked first, and each candidate that beats what is
    # held is saved at once, with the stored events it still trusts: a mirror
    # that stalls the pull cannot keep a revocation published there from
    # being recorded.
    cands, first_error, best = [], None, None
    for is_second, url, getter in ((True, second, get2), (False, base, get)):
        if url is None:
            continue
        try:
            m = manifest.load(getter(url + "manifest.json"), previous=floor)
        except manifest.ManifestError:
            err = "bad manifest"
        except Exception as e:
            err = _kind(e)
        else:
            if floor is not None and m.issued_at < floor.issued_at:
                err = "bad manifest"
            elif not manifest.verify(m, root_pubkey):
                err = "manifest not signed by the trust root"
            else:
                err = None
                cands.append((m.version, is_second, m))
                if best is None or (m.version, is_second) > best:
                    best = (m.version, is_second)
                    early = PullResult()
                    state.accept(root_pubkey, m,
                                 _retain(_filter(before, [], m, floor, early, channels, now), rnow, early))
                    state.save_events()
        if is_second:
            extra["second_origin"] = err or "ok"  # never by itself a pull error
        elif err:
            first_error = err
    if not cands:
        return fail(first_error or "unreachable")
    m = max(cands, key=lambda c: c[:2])[2]
    res.manifest = m

    def settle(fetched: list, error: str | None, keep=None, at=None) -> PullResult:
        """Accept the manifest with the stored events it still trusts plus
        ``fetched``, and record the outcome. A verified manifest is accepted
        even when the pull fails later: its revocations apply to the stored
        events at once. ``at``: the retention clock, when not ``rnow``."""
        at = rnow if at is None else at
        dropped = Counter()
        box = PullResult(dropped=dropped)
        kept = _filter(before, fetched, m, floor, box, channels, now)
        if keep is not None:
            kept = {eid: ev for eid, ev in kept.items() if eid in keep}
        kept = _retain(kept, at, box)
        if (len(kept) > MAX_STORED_EVENTS
                or state.size_with(root_pubkey, m, kept) > MAX_STORED_BYTES):
            dropped.clear()
            # nothing new is stored, so the checkpoint this pull fetched is not accepted
            # either: what is kept is aged by the clock the reader already held
            kept = _retain(_filter(before, [], m, floor, box, channels, now), rnow, box)
            error = error or "state limit reached: new events not stored"
        if not res.dropped:  # a failed step may already have counted what it refused
            res.dropped = dropped
        res.new_events = sorted((ev for eid, ev in kept.items() if eid not in before),
                                key=lambda e: (e["created_at"], e["id"]))
        state.accept(root_pubkey, m, kept)
        res.error = error
        return res

    def done() -> PullResult:
        record(res.error is None, res.error)
        state.save_pull()
        return res

    def events_files() -> tuple[list, str | None]:
        fetched = []
        for name in FILES:
            try:
                fetched += _events_file(get(base + name), name)
            except ValueError:
                return [], "bad event file"
            except Exception as e:
                return [], _kind(e)
        return fetched, None

    if not check:
        # The writers' pull: every verified event, as before the checkpoint.
        # A verified manifest is accepted even when an event file is
        # unreadable or the store is full; nothing here touches state.trust.
        fetched, error = events_files()
        settle(fetched, error)
        return done()

    # 2. the checkpoint key certificate: the root's word on which key signs
    # checkpoints for this manifest. The newest one the root signed is saved
    # at once, before any checkpoint is judged and even when it is itself
    # expired: a mirror must not be able to keep a key rotation from being
    # recorded, and an expired replacement must never revive its predecessor.
    cert = _choose_cert(m, root_pubkey, now, old_cert,
                        [(get, base)] + ([(get2, second)] if second is not None else []))
    if cert is not None and (old_cert is None or cert.event["id"] != old_cert.event["id"]):
        state.set_trust(root_pubkey, cert, old_cp, old_applied if old_applied is not None else ())
        state.save_trust()
    if cert is None or cpt.cert_problem(cert, m, now) is not None:
        settle([], "no checkpoint key certificate")
        return done()
    # 3. the checkpoint
    cp, error = _load_checkpoint(get, base, cert, m, now, old_cp)
    if cp is None:
        settle([], error)
        return done()
    # 4. events; then completeness: every listed event must be here
    fetched, error = events_files()
    if error:
        settle([], error)
        return done()
    probe = PullResult()
    have = _filter(before, fetched, m, floor, probe, channels, now)
    if not cp.events <= set(have):
        res.dropped = probe.dropped  # what was refused (a future-dated event names a slow clock)
        settle([], "mirror incomplete")
        return done()
    # The applied set only grows here. Ids whose events left the store on disk
    # (as it was when this pull began) are dropped now, a pull later than the
    # save that removed them: an interrupted save never un-applies a stored event.
    if old_applied is None:  # the first checkpoint: what the older reader held stays applied
        old_applied = {eid for eid, ev in before.items() if _bound(ev, channels)}
    applied = (set(old_applied) & set(before)) | set(cp.events)
    # Only applied events are stored. An event no checkpoint lists yet is
    # fetched again by the pull that follows its checkpoint; kept here it
    # would be shown by the released reader if it were run on this state, and
    # it would let whoever can post crowd the store.
    settle(fetched, None, keep=applied, at=min(now, cp.created_at))
    if res.error is not None:  # the applied events do not fit: nothing new is trusted
        return done()
    # 5. save: the checkpoint file first, then the events, then the record.
    state.set_trust(root_pubkey, cert, cp, applied)
    state.save_trust()
    extra.update(checkpoint_seq=cp.seq, checkpoint_events=len(cp.events))
    return done()


def _choose_cert(m: Manifest, root: str, now: float, stored, sources):
    """The newest certificate the root signed for manifest ``m`` among the
    fetched ones, the bundled one and the stored one, not dated ahead of the
    clock and not older than the stored one (cpt.cert_order). Expiry is NOT
    a filter here: the newest certificate is the floor even when it has
    expired, so an expired replacement never hands authority back to the
    certificate it replaced. The caller checks cert_problem. None if none."""
    found = [stored] if stored is not None else []
    if root == TRUST_ROOT_PUBKEY and bundled_cert() is not None:
        found.append(bundled_cert())
    for getter, url in sources:
        try:
            found.append(cpt.load_cert(getter(url + "checkpoint-key.json")))
        except Exception:  # missing, unreachable, malformed: this source has none
            continue
    usable = [c for c in found if cpt.verify_cert(c, root)
              and cpt.cert_problem(c, m, now) in (None, "expired") and cpt.cert_order(c, stored) is None]
    return max(usable, key=lambda c: (c.issued_at, c.event["id"]), default=None)


def _load_checkpoint(get, base: str, cert, m: Manifest, now: float, stored):
    """(the mirror's checkpoint, None) when it may be accepted, else (None, the
    pull error)."""
    try:
        data = get(base + "checkpoint.json")
    except Exception:
        return None, "no checkpoint"
    try:
        cp = cpt.load_checkpoint(data)
    except cpt.CheckpointError:
        return None, "bad checkpoint"
    if not cpt.verify_checkpoint(cp, cert):
        return None, "bad checkpoint"
    problem = cpt.checkpoint_problem(cp, m, now)
    if problem == "dated ahead":
        return None, "checkpoint dated ahead of this clock"
    if problem is not None:
        return None, "bad checkpoint"
    order = cpt.checkpoint_order(cp, stored)
    return (cp, None) if order is None else (None, order)


def effective_manifest(state: State) -> Manifest | None:
    """The stored manifest of the current root, or the bundled one when the
    current root is the pinned root and the bundle is newer: a revocation
    shipped in the package governs cached events before any pull succeeds."""
    m = state.manifest
    if m is not None and state.manifest_root == TRUST_ROOT_PUBKEY:
        b = bundled_manifest()
        if b is not None and b.version > m.version:
            return b
    return m


def freshness(state: State, now: float | None = None, channels=None) -> tuple[int | None, int | None]:
    """(newest created_at among the stored channel events a current key
    signed, the manifest's issued time), from the effective manifest; None,
    None before any pull. Signed times only: a mirror's generated_at is not.
    An event dated more than MAX_AHEAD_S after ``now`` is left out: one event
    dated years ahead must not look like fresh news for years. With a damaged
    channel spec there is no newest event."""
    m = effective_manifest(state)
    if m is None:
        return None, None
    now = time.time() if now is None else now
    if channels is None:
        try:
            channels = channel_ids()
        except ChannelSpecError:
            channels = frozenset()
    newest = max((ev["created_at"] for ev in state.events.values()
                  if manifest.role_of(m, ev["pubkey"]) is not None and _bound(ev, channels)
                  and ev["created_at"] <= now + MAX_AHEAD_S), default=None)
    return newest, m.event["created_at"]  # created_at equals issued_at (manifest.load)


_CERT_REASON = {"other manifest": "checkpoint key certificate is for another manifest",
                "dated ahead": "checkpoint key certificate dated ahead of this clock",
                "expired": "checkpoint key certificate expired"}
_CP_REASON = {"other manifest": "checkpoint is for another manifest",
              "dated ahead": "checkpoint dated ahead of this clock"}


def unverified(state: State, now: float | None = None) -> str | None:
    """Why what this reader shows may not be trusted to be complete right now,
    or None. The CLI auto-applies nothing while this is not None.

    In order: the last pull was not a finished, checked one (it failed, was
    interrupted, checked no checkpoint, or there was none: a refused pull
    must stop auto-apply even while the earlier checkpoint is still fresh);
    no certificate or checkpoint is stored; the certificate does not fit the
    effective manifest or the clock; the stored checkpoint is not the
    certified key's (the certificate was replaced); it does not fit the
    manifest or the clock (a clock set back lands here); an event it lists
    is not stored (an interrupted save); it is past its validity."""
    now = time.time() if now is None else now
    last, root = state.last_pull, state.manifest_root
    if last.get("checkpoint_ok") is not True:
        if not last:
            return "no pull yet"
        if last.get("error") == "interrupted":
            return "the last pull was interrupted"
        if last.get("error"):
            return f"the last pull failed ({last['error']})"
        return "the last pull checked no checkpoint"
    m = effective_manifest(state)
    if m is None:
        return "no pull yet"
    cert, cp = state.cert_for(root), state.checkpoint_for(root)
    if cert is None:
        return "no checkpoint key certificate"
    problem = cpt.cert_problem(cert, m, now)
    if problem is not None:
        return _CERT_REASON[problem]
    if cp is None:
        return "no checkpoint"
    if not cpt.verify_checkpoint(cp, cert):
        return "checkpoint is not signed by the certified key"
    problem = cpt.checkpoint_problem(cp, m, now)
    if problem is not None:
        return _CP_REASON[problem]
    if not cp.events <= set(state.events):
        return "stored events do not match the checkpoint"
    if now > cpt.fresh_until(cp):
        return "checkpoint out of date"
    return None


def stale_since(state: State, now: float | None = None) -> int | None:
    """None while the reader is verified (``unverified`` is None); else the
    signed time since which nothing was verified complete: the accepted
    checkpoint's, else the newest trusted event's, else the manifest's, else
    (no manifest at all) the time of the last pull attempt. Non-null in every
    unverified state on purpose: the session-start hook members installed
    looks for exactly this field. A frozen or replayed mirror verifies on
    every pull, and its checkpoint running out is how a reader notices."""
    now = time.time() if now is None else now
    if unverified(state, now) is None:
        return None
    cp = state.checkpoint_for(state.manifest_root)
    if cp is not None:
        return cp.created_at
    newest, issued = freshness(state, now)
    for t in (newest, issued, state.last_pull.get("at")):
        if isinstance(t, int):
            return t
    return int(now)


# ---------------------------------------------------------------- advisories

def _thread_ref(ev: dict) -> str | None:
    """The thread root an event replies to (NIP-10 marked e tags), or None."""
    marked = {t[3]: t[1] for t in ev.get("tags", [])
              if len(t) >= 4 and t[0] == "e" and t[3] in ("root", "reply")}
    return marked.get("root") or marked.get("reply")


def _patch(content: str) -> dict | None:
    block = schema._last_block(content) if isinstance(content, str) else None
    if not isinstance(block, str):
        return None
    try:
        obj = json.loads(block, object_pairs_hook=schema._no_duplicates,
                         parse_constant=schema._reject_constant)
    except (ValueError, RecursionError):
        return None
    return obj if isinstance(obj, dict) else None


def _fixed_holds(old: str | None, new: str | None) -> bool:
    """``fixed`` never falls. None (no version is known to fix it) is the
    highest: it may be reached, never left. check.plan takes an upgrade's
    version from ``fixed``, so this holds whatever the range is."""
    if new is None or new == old:
        return True
    a, b = versions.parse(old), versions.parse(new)
    return a is not None and b is not None and b > a


def _covered(p, by: list) -> bool:
    """One product entry of ``by`` stands for ``p``: the same ecosystem and
    name (as check.match compares names), a range that matches every
    installation ``p``'s matches, and a ``fixed`` that is not lower."""
    return any(q.ecosystem == p.ecosystem and q.name.lower() == p.name.lower()
               and _fixed_holds(p.fixed, q.fixed)
               and versions.covers(p.affected, p.fixed, q.affected, q.fixed) for q in by)


def _kept(a, by: list) -> bool:
    """One action of ``by`` says what ``a`` says: the same verb, target and
    value. An upgrade's version is ordered as ``fixed`` is: one with a
    higher version, or with none, stands for it."""
    return any((b.verb, b.target) == (a.verb, a.target)
               and (b.value == a.value or (a.verb == "upgrade" and _fixed_holds(a.value, b.value)))
               for b in by)


def _listed(s, by: list) -> bool:
    return any(t.url == s.url for t in by)


# field -> (the schema's list limit, "an entry of this list stands for that one")
_WIDEST = {"products": (50, _covered), "actions": (20, _kept), "sources": (20, _listed)}
LIST_LIMITS = {k: v[0] for k, v in _WIDEST.items()}  # what one event may carry; a joined list may hold more
# Past this many entries a list is no longer compared entry by entry: each
# comparison is a scan, and a key that floods a thread with entries none of
# which stands for another would otherwise cost every read their square.
_JOIN_SCAN = 200


def _join(cur: list, new: list, stands) -> list:
    """``cur`` and ``new`` as one list in which every entry of either is
    stood for: an entry of ``new`` that ``cur`` already stands for adds
    nothing; any other is appended and replaces the entries it stands for.
    Nothing a member matched or was shown through either list is lost, in
    whatever order the lists arrive. A list past _JOIN_SCAN entries only
    grows: an entry not already in it is appended without comparison, which
    loses nothing either."""
    out = list(cur)
    have = set(out)
    for q in new:
        if q in have:
            continue
        if len(out) <= _JOIN_SCAN:
            if stands(q, out):
                continue
            out = [p for p in out if not stands(p, [q])]
            have = set(out)
        out.append(q)
        have.add(q)
    return out


def _apply_patch(adv: Advisory, patch: dict, role: str, dropped: Counter | None = None) -> Advisory | None:
    """The advisory with ``patch`` applied, or None if the patch is invalid.
    Omitted field: unchanged. Present: replaced whole. null: cleared (only
    nullable fields validate as null); {} changes nothing. ``id`` and
    ``posted_by`` may not appear (B3 compose's contract): the thread keeps
    its root's id and role.

    A patch from any role but curator never shrinks what a member sees
    (ai-tools-alerts#tyje). One that lowers ``level`` or sets ``expires_at``
    is invalid. Its ``products``, ``actions`` and ``sources`` do not replace
    the thread's: they are joined to them (_join), so the patch can add an
    entry or widen one and can take nothing away. A patch whose list does not
    itself stand for everything the thread held is counted once in
    ``dropped`` as ``narrowing``. The join does not depend on the order the
    patches are read in, so a patch dated before one already applied cannot
    undo it. A joined list may pass the schema's limit; the limit is checked
    on what each event carries. A curator's patch replaces the fields it
    names.

    A narrowing of ``products`` is not lost with that (ai-tools-alerts#swfe):
    ``_bot_reply`` keeps the list as the thread's published narrowing, and
    ``standing`` shows it once the member's own check confirms it or it has
    stood UNCHECKED_LOWERING_S in signed checkpoints."""
    if set(patch) - (_PATCH_KEYS - {"id", "posted_by"}):
        return None  # B3's contract: id and posted_by may not appear
    if role != "curator":
        if "expires_at" in patch:
            return None
        lvl = patch.get("level", adv.level)
        if not isinstance(lvl, str) or lvl not in _RANK or _RANK[lvl] < _RANK[adv.level]:
            return None
    # A joined list past the limit must not fail a patch that omits it.
    base = asdict(replace(adv, **{k: getattr(adv, k)[:limit] for k, limit in LIST_LIMITS.items()}))
    try:
        new = schema.validate({**base, **patch, "posted_by": adv.posted_by})
    except ValueError:
        return None
    keep = {k: getattr(adv, k) for k in _WIDEST if k not in patch}
    if role != "curator":
        named = [k for k in _WIDEST if k in patch]
        if dropped is not None and any(
                len(getattr(adv, k)) > _JOIN_SCAN  # no single event's list stands for a flooded one
                or not all(_WIDEST[k][1](e, getattr(new, k)) for e in getattr(adv, k)) for k in named):
            dropped["narrowing"] += 1
        keep.update((k, _join(getattr(adv, k), getattr(new, k), _WIDEST[k][1])) for k in named)
    return replace(new, **keep)


def _first_line(content: str) -> str:
    """The first line, split on CommonMark line endings, stripped (as C1's
    exporter reads a retraction)."""
    return schema._LINES.split(content)[0].strip()


def _clean(line: str) -> str:
    """The line without the characters schema rejects in a title (bidi
    controls; Cc, Cf, Cs, Zl, Zp), so no escape reaches a terminal."""
    return "".join(ch for ch in line if ch not in schema._BIDI and unicodedata.category(ch)
                   not in ("Cc", "Cf", "Cs", "Zl", "Zp")).rstrip()


def parse_translation(content) -> tuple[str, str | None, str] | None:
    """(lang, of, text) of a translation reply: first line ``lang: <code>``,
    an optional ``of: <event id>`` line (None: the root), a blank line, the
    text. None when malformed, empty, or carrying an aitools-alert fence: a
    lang reply is never a patch, and one with a block is ignored entirely."""
    if not isinstance(content, str) or len(content) > schema.MAX_POST_CHARS:
        return None
    if schema._last_block(content) is not schema._NONE:
        return None
    lines = schema._LINES.split(content)
    m = _LANG.fullmatch(lines[0].strip())
    if m is None or len(lines) < 3:
        return None
    of, rest = None, lines[1:]
    if rest[0].strip():
        o = _OF.fullmatch(rest[0].strip())
        if o is None:
            return None
        of, rest = o.group(1), rest[1:]
    if not rest or rest[0].strip():
        return None
    text = "\n".join(_clean(x) for x in rest).strip("\n")[:MAX_TRANSLATION_CHARS].strip()
    return (m.group(1), of, text) if text else None


def translation_title(text: str, adv_id: str | None = None) -> str:
    """A translation's title: its first non-blank line, at most 200
    characters, marked as schema marks the title of a synthetic id."""
    title = next((x.strip()[:200] for x in text.split("\n") if x.strip()), "")
    if schema.is_synthetic(adv_id) and not title.startswith(schema.SYNTHETIC + ": "):
        title = f"{schema.SYNTHETIC}: {title}"
    return title


def _renewal(ev: dict, role: str) -> tuple | None:
    """(the claim's id case-folded, confirmed_at, checked_at, the event's
    created_at) when ``ev`` is a relay-bot event carrying a well-formed claim
    of a level, checked no later than the event is dated; else None. The
    claim's own level and ruleset number are not compared, and its fields are
    not judged: a renewal says when, the source check says whether. Never
    raises."""
    if role != "relay-bot":
        return None
    try:
        c = ruleset.parse_claim(wire.claim_of(ev))
        if c["level"] == ruleset.NONE or c["checked_at"] > ev["created_at"]:
            return None
        return c["id"].casefold(), c["confirmed_at"], c["checked_at"], ev["created_at"]
    except Exception:  # a hostile claim never stops the other threads
        return None


def _is_root(ev: dict) -> bool:
    """A root carries no e tag at all (as C1's exporter): an event whose only
    e tags are unmarked mentions is neither a root nor a reply."""
    return not any(t and t[0] == "e" for t in ev["tags"])


def advisories(state: State, dropped: Counter | None = None, checkpointed: bool = True) -> list[Thread]:
    """Every thread built from the applied events under the current manifest.

    Applied: the stored events an accepted checkpoint has listed (the applied
    set, which only grows: see the module text). Before a first checkpoint
    was ever accepted, every stored event, as the older reader showed them.
    ``checkpointed=False`` is the writers' view (the curator command): every
    stored event, so a thread posted a minute ago can be amended.

    Replies apply to their root in (created_at, id) order. A curator reply
    whose first line is ``retract`` retracts the thread; one whose
    first line is ``level: high`` or ``level: notice`` lowers the level. A
    reply's ``aitools-alert`` block, if any, is a patch (see _apply_patch):
    a relay-bot's adds to or widens the products, actions and sources of
    its thread and never narrows them (an attempt is counted as
    ``narrowing``), even when the rest of it is refused. A narrower
    ``products`` list is kept beside the thread as ``narrowed``, applied
    nowhere here (ai-tools-alerts#swfe: ``_narrowing``, ``standing``).
    On a thread a curator posted, a curator's word is final and a relay-bot
    reply is discussion; only its ``lang:`` translations count
    (ai-tools-alerts#bq8v). On a relay-bot thread a curator's word is held,
    not final (ai-tools-alerts#c1g2): each curator action sets
    ``held_until`` 14 days after its date, the thread built here is the
    thread as the curator left it, and ``wide`` is the same thread with every
    reply under the relay bot's rules. While held, a relay-bot reply that
    names a higher level raises the thread at once and its other changes go
    to ``wide`` only. A curator reply dated after ``held_until`` meets
    ``wide``. A relay-bot block that is exactly a lower level is kept as
    ``offered`` and applied nowhere here. ``standing`` decides, with a clock
    and the member's check, which of the states a reader shows. A patch that fails validation, or raises, is counted and skipped.
    A reply whose first line starts with ``lang:`` is a translation and
    nothing else (see parse_translation), under the same discussion rule. It
    is kept, the latest per language and target, when it names the root
    (``of`` absent or the root id) or a reply that changed the advisory; a
    relay-bot translation never replaces a curator's. The thread's text is
    the root's translation with each change's appended (see _composed).
    Only events bound to an alert channel take part (``_bound``); a damaged
    channel spec raises ChannelSpecError.
    Last, a thread is retracted if any id it has carried (the root's id and
    aliases, and aliases a curator patch itself supplied) is in the manifest's
    ``retracted``, whoever posted or retracted it, compared case-folded as
    the poster's ledger compares ids. Deletion events (kinds 5 and 9005) are
    never read.

    A root from any role but curator has its ``expires_at`` dropped (counted
    ``bot-expiry``): expiry is computed from claims, see ``active``. A thread
    whose root carries a claim has its ``renewals`` (_renewal): from the root,
    from every reply (on a curator's own thread: while it is not retracted),
    discussion included, and one for each relay-bot reply whose block names
    a level. Any other thread has
    none. Which events give a renewal never depends on the order of replay.
    """
    m = effective_manifest(state)
    if m is None:
        return []
    channels = channel_ids()
    applied = state.applied_for(state.manifest_root) if checkpointed else None
    return threads_from([ev for ev in state.events.values() if _bound(ev, channels)
                         and (applied is None or ev["id"] in applied)], m, dropped)


class _Hold:
    """What ``threads_from`` keeps for a relay-bot thread beside the state a curator's
    word gives it (c1g2): ``wide``, the widest state; ``until``, when the curator's hold
    ends (None: none in force, and then the thread's advisory is ``wide`` itself);
    ``offered``, the level last published below ``wide``'s. And the history a check is
    asked with (``note``), from every state the thread has shown, the curator's held
    one included: ``aliases``, every alias, in the order they came; ``fixed``, per
    product (ecosystem and name) the first fixed version stated for it; ``names``, per
    product, its name exactly as written, the first entry that carried it. A later reply may drop an
    alias, clear ``fixed`` or put a product in another spelling in an entry's place:
    each is a widening for matching, and none may weaken what a check is asked about."""
    __slots__ = ("wide", "until", "offered", "aliases", "fixed", "names", "_seen", "offered_by",
                 "narrowed", "narrowed_by", "keys")

    def __init__(self, adv: Advisory):
        self.until, self.offered, self.aliases, self.fixed, self.names, self._seen = None, None, [], {}, {}, set()
        self.offered_by = None  # tavj: the relay-bot reply that published ``offered``
        self.narrowed = self.narrowed_by = None  # swfe: the published narrowing and its reply
        self.keys: dict = {}  # narrow_key of every narrowing published, in order
        self.widen(adv)

    def note(self, adv: Advisory) -> None:
        for a in adv.aliases:
            if a not in self._seen:  # a set: a thread flooded with aliases must not cost their square
                self._seen.add(a)
                self.aliases.append(a)
        for p in adv.products:
            self.names.setdefault((p.ecosystem, p.name), p)
            if p.fixed is not None:
                self.fixed.setdefault((p.ecosystem, p.name), p.fixed)

    def widen(self, adv: Advisory) -> None:
        self.wide = adv
        self.note(adv)


def _missing(h: _Hold) -> tuple:
    """The first entry of each product (ecosystem and name, 2mgd: an entry of the same
    name under another ecosystem is another product and stands for nothing) the thread
    has carried and ``wide`` no longer does. The join compares names without case and
    an entry spelled otherwise can stand in for the original: the original, with the
    fixed version it stated, is still what a lowering is checked against."""
    have = {(p.ecosystem, p.name) for p in h.wide.products}
    return tuple(p for key, p in h.names.items() if key not in have)


def _bot_patch(adv: Advisory, p: dict, dropped: Counter | None = None) -> tuple:
    """(``adv`` with block ``p`` applied under the relay bot's rules, the block as it was
    applied), or (None, ...) when nothing of it applies. A block ``_apply_patch`` refuses
    is counted ``bad-patch``, and what it adds to products, actions or sources still
    counts: were it lost with the block, a block dated earlier that raises the level
    would take it away."""
    try:
        new = _apply_patch(adv, p, "relay-bot", dropped)
    except Exception:  # a hostile patch never stops the other threads
        new = None
    if new is None:
        if dropped is not None:
            dropped["bad-patch"] += 1
        p = {k: p[k] for k in _WIDEST if k in p}
        try:
            new = _apply_patch(adv, p, "relay-bot") if p else None
        except Exception:
            new = None
        if new == adv:
            new = None
    return new, p


def narrow_key(root_id: str, products=()) -> str:
    """What a member's refusal of a published narrowing is remembered by (swfe): the
    thread's root and the set of entries the list holds, so the same entries sent again
    in another reply, in another order or twice over, are the same refusal. With no
    products: the mark that some narrowing of this thread has been refused."""
    entries = sorted({json.dumps(asdict(p), sort_keys=True, separators=(",", ":")) for p in products})
    text = json.dumps([root_id, entries], separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _narrowing(adv: Advisory, p: dict) -> tuple | None:
    """What block ``p`` publishes about the products of ``adv`` (swfe). None: nothing (it
    names none, or its list does not validate). (): its list stands for every entry
    ``adv`` holds. Otherwise the list as the schema read it: a narrowing, which the join
    never applies and ``standing`` may. Past _JOIN_SCAN entries ``adv`` is not compared
    entry by entry (no single event's list stands for a flooded one), and every valid
    list is a narrowing: a flooded thread can still be corrected. Never raises."""
    if "products" not in p:
        return None
    try:
        base = asdict(replace(adv, **{k: getattr(adv, k)[:limit] for k, limit in LIST_LIMITS.items()}))
        stated = schema.validate({**base, "products": p["products"], "posted_by": adv.posted_by}).products
    except Exception:  # a hostile block never stops the other threads
        return None
    covers = len(adv.products) <= _JOIN_SCAN and all(_covered(e, stated) for e in adv.products)
    return () if covers else tuple(stated)


def _bot_reply(t: list, h: _Hold, ev: dict, p: dict, dropped: Counter) -> None:
    """One relay-bot block on a relay-bot thread (c1g2). A level-only lowering
    (spec/wire.md rule 1) is published, not applied: ``standing`` applies it when the
    member's own check confirms it. Anything else goes to the widest state. With no
    curator's hold in force that is the thread. With one, only a higher level reaches
    the thread now, and never a retracted one; the rest shows when the hold lapses."""
    if set(p) == {"level"} and wire.is_lowering(p, h.wide.level):
        if h.offered != p["level"] or h.offered_by is None:
            h.offered_by = ev["id"]  # the same level offered again keeps the first reply: its wait goes on
        h.offered = p["level"]
        if h.until is not None and not t[1] and _RANK[p["level"]] > _RANK[t[0].level]:
            # below the widest level and above what the curator holds it at: a raise to a reader
            t[0], t[2], t[7] = replace(t[0], level=p["level"]), ev["created_at"], True
            if t[6][-1] != ev["id"]:
                t[6].append(ev["id"])
        return
    offer = _narrowing(h.wide, p)  # against the widest state before this reply joins it
    if offer is not None and offer != h.narrowed:  # the same list again keeps the first reply: its wait goes on
        h.narrowed, h.narrowed_by = (offer, ev["id"]) if offer else (None, None)
        if offer:
            h.keys.setdefault(narrow_key(t[6][0], offer))
    new, used = _bot_patch(h.wide, p, dropped)
    if new is None:
        return
    h.widen(new)
    t[10].update(i.casefold() for i in new.aliases)  # for renewals: an alias once held stays
    level = used.get("level")
    if level is not None:
        h.offered = h.offered_by = None  # a block that applied names the widest state's level or raises it
    if h.until is None:
        t[0], t[2] = new, ev["created_at"]
        t[7] = t[7] or "title" in used or "level" in used
    elif not t[1] and level is not None and _RANK[level] > _RANK[t[0].level]:
        t[0], t[2], t[7] = replace(t[0], level=level), ev["created_at"], True
    else:
        return
    if t[6][-1] != ev["id"]:
        t[6].append(ev["id"])


def threads_from(events, m: Manifest, dropped: Counter | None = None) -> list[Thread]:
    """advisories() over any verified events (the exporter's too)."""
    dropped = dropped if dropped is not None else Counter()
    roots, replies = {}, []
    for ev in events:
        role = manifest.role_of(m, ev.get("pubkey"))
        if role is None or ev.get("kind") in _DELETION_KINDS:
            continue  # a deletion request is never read, even from a trusted key
        ref = _thread_ref(ev)
        if ref is not None:
            replies.append((ev, role, ref))
            continue
        if not _is_root(ev):
            continue  # unmarked e tags only: a mention, not part of a thread
        adv = schema.parse_post(ev["content"])
        if adv is None:
            dropped["no-block"] += 1
            continue
        if role != "curator" and adv.expires_at is not None:
            dropped["bot-expiry"] += 1
            adv = replace(adv, expires_at=None)
        roots[ev["id"]] = [replace(adv, posted_by=role), False, ev["created_at"], role == "curator",
                           {i.casefold() for i in (adv.id, *adv.aliases)}, {}, [ev["id"]], False,
                           [], _renewal(ev, role), {i.casefold() for i in (adv.id, *adv.aliases)},
                           None if role == "curator" else _Hold(replace(adv, posted_by=role)),
                           [] if role == "curator" else [(adv.level, wire.claim_of(ev))]]
    for ev, role, ref in sorted(replies, key=lambda r: (r[0]["created_at"], r[0]["id"])):
        t = roots.get(ref)
        if t is None:
            continue
        h, at = t[11], ev["created_at"]
        if h is None and t[1]:
            continue  # a curator's own thread, retracted: for good
        if role == "curator" and h is not None and h.until is not None and at > h.until:
            # c1g2: the hold had lapsed when the curator wrote this; it meets the widest
            # state, so a later title fix cannot bring a lapsed lowering back. Only a
            # curator's own date does this: no relay-bot event, however dated, ends a hold.
            t[0], t[1], t[3], h.until = h.wide, False, False, None
        if (rn := _renewal(ev, role)) is not None:
            t[8].append(rn)
        if role != "curator":
            # A reply that names a level is news of its own date, with or without a
            # claim: a raise stands from then, never from an older confirmation of a
            # lower level. Judged by the event alone, not by whether it raised when the
            # thread was replayed, so no event dated earlier can take this away.
            named = (_patch(ev["content"]) or {}).get("level")
            if isinstance(named, str) and named in _RANK:
                t[8].append((t[0].id.casefold(), at, at, at))
                if h is not None:
                    t[12].append((named, wire.claim_of(ev)))
        first = _first_line(ev["content"])
        if first.startswith("lang:"):  # a translation, never a patch or a retraction
            tr = None if t[1] else parse_translation(ev["content"])
            if tr is not None and (tr[1] or ref) in t[6]:  # the root or a change to it
                prev = t[5].setdefault(tr[1] or ref, {}).get(tr[0])
                if role == "curator" or prev is None or not prev[2]:  # a curator's stands
                    t[5][tr[1] or ref][tr[0]] = (tr[2], at, role == "curator")
            continue
        p = _patch(ev["content"])
        if role != "curator":
            if h is not None and p is not None and first != "retract":  # the bot has no retract; such a reply is ignored whole
                _bot_reply(t, h, ev, p, dropped)
            continue  # on a curator's own thread: discussion
        if first == "retract":
            t[1], t[2] = True, at
            if h is not None:  # held, and published for the member's check; said again, it renews
                h.offered, h.until, t[3], h.offered_by = NONE, at + CURATOR_HOLD_S, True, None
            continue
        if t[1]:
            continue  # retracted and held: only a retraction renews it
        acted = False
        if first.startswith("level:"):
            want = first[len("level:"):].strip()
            if want in ("high", "notice") and _RANK[want] <= _RANK[t[0].level]:
                if _RANK[want] < _RANK[t[0].level]:
                    t[0], t[2] = replace(t[0], level=want), at
                    t[6].append(ev["id"])
                    t[7] = True
                acted = True  # the same level said again renews a hold
                if h is not None:
                    h.offered, h.offered_by = want if _RANK[want] < _RANK[h.wide.level] else None, None
                    t[12].append((want, None))  # a curator's word carries no claim
        if p is not None:
            try:
                new = _apply_patch(t[0], p, role, dropped)
            except Exception:  # a hostile patch never stops the other threads
                new = None
            if new is None:
                dropped["bad-patch"] += 1
            else:
                t[0], t[2], acted = new, at, True
                t[10].update(i.casefold() for i in new.aliases)  # for renewals: an alias once held stays
                if t[6][-1] != ev["id"]:
                    t[6].append(ev["id"])
                t[7] = t[7] or "title" in p or "level" in p
                if "aliases" in p:  # only aliases a curator wrote:
                    t[4].update(i.casefold() for i in new.aliases)  # a bot's never list a thread
                if h is not None:
                    if "products" in p:
                        h.narrowed = h.narrowed_by = None  # swfe: the curator's list is the last word on products
                    h.note(new)  # a fix or an alias the curator supplied is part of the thread's history
                    # The widest state takes a curator's reply as it takes the bot's: what it
                    # adds or raises stays after the hold, what it takes away does not.
                    # Without its expiry: the bot's rules refuse a block that names one whole,
                    # and a raise sent with an expiry must not be lost with it.
                    wide, used = _bot_patch(h.wide, {k: v for k, v in p.items() if k != "expires_at"})
                    if wide is not None:
                        h.widen(wide)
                    if isinstance(p.get("level"), str) and p["level"] in _RANK:
                        h.offered = p["level"] if _RANK[p["level"]] < _RANK[h.wide.level] else None
                        h.offered_by = None
                        t[12].append((p["level"], None))
        if acted:
            t[3] = True
            if h is not None:
                h.until = at + CURATOR_HOLD_S
    listed = {i.casefold() for i in m.retracted}
    out = []
    for rid, (a, r, u, cur, ids, tr, changes, retitled, rns, first, ok, h, said) in sorted(
            roots.items(), key=lambda kv: (kv[1][2], kv[0])):
        text, at = _composed(a, tr, changes, retitled)
        gone = not ids.isdisjoint(listed)  # the manifest's word: for good, nothing lapses
        hold = {} if h is None or gone else {"wide": h.wide, "held_until": h.until, "offered": h.offered,
                                             "held_aliases": tuple(h.aliases),
                                             "held_fixed": tuple(sorted(h.fixed.items())),
                                             "held_products": _missing(h), "stated": tuple(said),
                                             "offered_by": h.offered_by if h.offered is not None else None,
                                             "narrowed": h.narrowed, "narrowed_by": h.narrowed_by,
                                             "narrowings": tuple(h.keys)}
        # ``ok``: every id and alias the thread has held. A later patch that drops an
        # alias must not take away a renewal made under it.
        enrolled = first is not None and first[0] in ok
        out.append(Thread(root_id=rid, adv=a, retracted=r or gone, updated_at=u,
                          translations=text, translated_at=at, curated=cur, **hold,
                          enrolled_at=first[3] if enrolled else None,
                          renewals=tuple(sorted(x[1:] for x in [first, *rns] if x[0] in ok)) if enrolled else ()))
    return out


def _composed(adv: Advisory, tr: dict, changes: list, retitled: bool) -> tuple[dict, dict]:
    """Per language, the root's translation followed by each change's, when
    the root and every change since have one (else that language is left
    out: a translation never describes a superseded advisory). After a title
    or level change the first line is the English title."""
    text, at = {}, {}
    for lang in tr.get(changes[0], {}):
        parts = [tr.get(c, {}).get(lang) for c in changes]
        if None in parts:
            continue
        lines = "\n\n".join(p[0] for p in parts).split("\n")
        if retitled:
            lines[0] = adv.title
        text[lang], at[lang] = "\n".join(lines), max(p[1] for p in parts)
    return text, at


def head_clock(state: State) -> tuple[int | None, frozenset | None]:
    """(the issue time of the stored checkpoint of the state's root, the ids
    it lists): the clock ``active`` judges expiry by. (None, None) when there
    is no checkpoint, and when an event it lists is not stored: a save
    interrupted between the checkpoint and the events leaves a later
    checkpoint over an earlier store, in which a renewal may be missing."""
    cp = state.checkpoint_for(state.manifest_root)
    if cp is None or not cp.events <= set(state.events):
        return None, None
    return cp.created_at, cp.events


def _held(t: Thread, now) -> bool:
    return t.held_until is not None and (now is None or now <= t.held_until)


def widest(t: Thread) -> Advisory:
    """What a member's check is asked about: the widest state of a relay-bot thread with
    every alias it has held, every product name it has carried and, for a product whose
    entry states no fixed version, the one the thread stated before. The source is
    read per exact product name and its level is held to what the post can be acted on
    with (9kgk), so a reply that drops an alias, clears ``fixed`` or respells a product
    must not be able to make the source read lower than it did, or not at all."""
    fixed = dict(t.held_fixed)
    return replace(t.wide, aliases=list(t.held_aliases),
                   products=[replace(p, fixed=fixed[p.ecosystem, p.name])
                             if p.fixed is None and (p.ecosystem, p.name) in fixed else p
                             for p in (*t.wide.products, *t.held_products)])


def asks(t: Thread, now: float | None = None) -> list:
    """The levels ``standing`` asks the check about for this thread: what a curator's
    hold lowered it to ("none" for a retraction) while the hold is in force, and the
    published lower level. [] for a thread with neither."""
    out = []
    if t.wide is None:
        return out
    if _held(t, now):
        if t.retracted:
            out.append(NONE)
        elif _RANK[t.adv.level] < _RANK[t.wide.level]:
            out.append(t.adv.level)
    if t.offered is not None and t.offered not in out:
        out.append(t.offered)
    return out


def offers(threads, held: dict, now, listed) -> dict:
    """The member's record of unchecked relay-bot lowerings and narrowings as it should be
    under the checkpoint issued at ``now`` that lists ``listed`` (``head_clock``): {the reply's id:
    the issue time of the checkpoint this machine held when it first saw one list the
    reply}. Kept: a reply that is still its thread's standing offer (``offered_by``, or
    ``narrowed_by`` for a published narrowing) and that the
    checkpoint lists, with its root, at the earlier of its recorded time and ``now``.
    Everything else is dropped, so a lowering a checkpoint stops listing, or one a raise
    replaced, starts again from nothing. Without a checkpoint the record is unchanged.
    Only signed checkpoint times enter it: never a reply's own date, which its signer
    chooses, and never this machine's clock."""
    if now is None or listed is None:
        return dict(held)
    out = {}
    for t in threads:
        # swfe: a published narrowing is recorded by its reply as a lowering is
        for i in (t.offered_by if t.offered not in (None, NONE) else None, t.narrowed_by):
            if i is not None and i in listed and t.root_id in listed:
                at = held.get(i)
                out[i] = int(min(at, now)) if type(at) is int else int(now)
    return out


def _stood(reply: str | None, now, since) -> bool:
    """The relay-bot reply has been listed by checkpoints UNCHECKED_LOWERING_S apart."""
    at = since.get(reply) if since is not None and reply is not None else None
    return now is not None and type(at) is int and now - at >= UNCHECKED_LOWERING_S


def standing(t: Thread, now: float | None = None, check=None, since=None) -> Thread:
    """The thread as it stands at ``now``: its level and state as ``_level_standing``
    decides them (c1g2, tavj), then its published narrowing (swfe).

    A narrowing is decided only on a relay-bot thread that is not retracted and that no
    curator's hold governs at ``now``. ``check.narrowing(widest state, the published
    list, the entries the thread shows)`` is the member's own source check of it: the
    sources are asked about the widest state, and the list is compared with what the
    thread shows, never with what ``widest`` filled in. True when the source states it, False
    when the source states otherwise, None when it does not settle it (and for a
    ``check`` without that attribute). True: the thread's products are the published
    list. None: the same once the reply has stood UNCHECKED_LOWERING_S in ``since`` by
    ``now``; until then ``narrow_waiting`` is set when ``since`` holds the reply. False:
    never, and ``narrow_refused`` is set. Only ``products`` change: the actions and
    sources stay the widest."""
    out = _level_standing(t, now, check, since)
    if t.wide is None or t.narrowed is None or out.retracted or _held(t, now):
        return out
    ask = getattr(check, "narrowing", None)
    said = ask(widest(t), t.narrowed, t.wide.products) if ask is not None else None
    if said is True or (said is None and _stood(t.narrowed_by, now, since)):
        return replace(out, adv=replace(out.adv, products=list(t.narrowed)))
    return replace(out, narrow_refused=said is False,
                   narrow_waiting=said is None and since is not None and t.narrowed_by in since)


def _level_standing(t: Thread, now: float | None = None, check=None, since=None) -> Thread:
    """The thread as it stands at ``now`` (c1g2). Only a relay-bot thread a curator
    acted on, or one with a published lowering, can differ from ``t``.

    ``check(advisory, level, stated)`` is the member's own source check of "this advisory
    at this level" ("none": retracted; ``stated`` is the thread's): True when the sources
    confirm it, False when they support more, None when they do not settle it (and for
    every thread when ``check`` is None). ``now`` is the clock a hold is judged by; None:
    no hold lapses. ``since``: the member's record of unchecked lowerings (``offers``);
    None: none ever applies unchecked.

    While a curator's hold is in force the thread is as the curator left it, unless the
    curator lowered or retracted it and the check says False: then it is the widest
    state, whole, and ``refused`` names the level. After the hold, and with none, it is
    the widest state: at the published lower level when the check says True (retracted
    for "none"; the CLI's check never says True for that), with ``refused`` set when
    it says False. A relay bot's lowering the check does not settle (None) applies once
    it has stood UNCHECKED_LOWERING_S in ``since`` by ``now`` (tavj); until then the
    thread is the widest state and ``waiting`` names the level when ``since`` holds its reply. So a lowering nobody can
    check lasts a curator's 14 days and no longer, a relay bot's applies after 72 hours of
    signed checkpoints, and one the member's source contradicts never applies at all."""
    if t.wide is None or (t.held_until is None and t.offered is None):
        return t

    def says(level):
        return check(widest(t), level, t.stated) if check is not None else None

    def base(refused=None, waiting=None) -> Thread:
        same = t.adv == t.wide and not t.retracted  # else the translations describe the held state
        return replace(t, adv=t.wide, retracted=False, curated=False, held_until=None, refused=refused,
                       waiting=waiting,
                       translations=t.translations if same else {}, translated_at=t.translated_at if same else {})

    if _held(t, now):
        ask = next(iter(asks(replace(t, offered=None), now)), None)
        return t if ask is None or says(ask) is not False else base(ask)
    said = says(t.offered) if t.offered is not None else None
    if said is True or (said is None and t.offered not in (None, NONE) and _stood(t.offered_by, now, since)):
        return replace(base(), retracted=True) if t.offered == NONE else replace(
            base(), adv=replace(t.wide, level=t.offered))
    # waiting: only where the wait can run out (a record is kept, and it holds this reply:
    # not for a CLI that applies nothing unchecked, not for a thread whose refusal stands)
    unsettled = (said is None and t.offered not in (None, NONE) and since is not None
                 and t.offered_by is not None and t.offered_by in since)
    return base(t.offered if said is False else None, t.offered if unsettled else None)


def active(threads: list[Thread], now: float | None = None, listed=None, check=None, *,
           decay: bool = True, since=None) -> list[Thread]:
    """Threads check should see: not retracted, not expired, each at the level
    it holds at ``now``, as it stands (``standing``).

    ``now`` is the issue time of the newest accepted checkpoint and ``listed``
    the ids it lists (``head_clock``), never this machine's clock: a frozen
    mirror stops the clock, so it can pin an alert and cannot end one. With
    ``now`` None nothing expires; with ``listed`` None every thread counts as
    listed. A thread whose root the checkpoint does not list keeps the level
    its events give.

    A curator's ``expires_at`` ends its thread once ``now`` is past it. A
    thread whose root carries a claim, and that no curator posted or amended,
    is shown at ``ruleset.Ruleset.level_at`` of its renewals and dropped when
    no level stands. While any of its renewals is on an event dated after the
    checkpoint (the poster's checkpoint lists the posts of its own run, which
    are dated after it) the thread keeps its level: the next checkpoint
    judges it. So every renewal is counted when the thread is judged, the
    root's among them, and no reply can end a thread sooner than the root
    alone would. Every other thread does not expire. A ruleset that cannot be
    loaded expires nothing, and neither does ``decay=False``: a reader whose
    ruleset the trust root calls out of date (``ruleset.outdated``) keeps the
    level a thread's events give. A curator's ``expires_at`` still ends its thread.

    Each thread is taken as it stands (``standing``, with ``check`` and ``since``): a
    curator's hold on a relay-bot thread lapses by the same clock, under a checkpoint that
    lists the root, and a thread whose hold lapsed decays by its claims again. An entry
    of ``since`` counts only while the checkpoint lists its reply."""
    out, rs = [], None
    if since is not None and listed is not None:
        since = {i: at for i, at in since.items() if i in listed}
    for t in threads:
        judged = now is not None and (listed is None or t.root_id in listed)
        t = standing(t, now if judged else None, check, since)
        if t.retracted:
            continue
        level = t.adv.level
        if judged:
            if t.adv.expires_at is not None:
                if now > t.adv.expires_at:
                    continue
            elif decay and t.enrolled_at is not None and not t.curated and all(at <= now for _, _, at in t.renewals):
                try:
                    rs = rs or ruleset.load()
                    level = rs.level_at(level, [(c, k) for c, k, _ in t.renewals], now)
                except Exception:  # a damaged spec file must not end alerts
                    level = t.adv.level
                if level == ruleset.NONE:
                    continue
        out.append(t if level == t.adv.level else replace(t, adv=replace(t.adv, level=level)))
    return out
