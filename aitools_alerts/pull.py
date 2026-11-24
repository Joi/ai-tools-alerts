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
trusted curator's retraction or by the manifest's ``retracted`` list.

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
claims keep its level standing (``ruleset.Ruleset.level_at``), and it decays
only under a stored checkpoint issued after that which lists its root. A
frozen mirror, a withheld renewal or a wrong clock therefore expire nothing;
retention takes its clock from the checkpoint too (``_fetch``).
"""

from __future__ import annotations

import copy
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
           "bundled_cert", "SECOND_TIMEOUT", "head_clock"]

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
    # the event's created_at). ``enrolled``: the root itself carries one; only then can
    # the thread decay. ``curated``: a curator posted or amended it; it never decays.
    renewals: tuple = ()
    enrolled: bool = False
    curated: bool = False


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
    names."""
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
    whose first line is ``retract`` retracts the thread for good; one whose
    first line is ``level: high`` or ``level: notice`` lowers the level. A
    reply's ``aitools-alert`` block, if any, is a patch (see _apply_patch):
    a relay-bot's adds to or widens the products, actions and sources of
    its thread and never narrows them (an attempt is counted as
    ``narrowing``), even when the rest of it is refused.
    Once a curator has posted or amended a thread, a relay-bot reply to it is
    discussion, so the bot can neither suppress, alter nor undo a curator's
    word; only its ``lang:`` translations still count (ai-tools-alerts#bq8v). A patch that fails validation, or raises, is counted and skipped.
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
    ``bot-expiry``): expiry is computed from claims, see ``active``. Each
    thread carries its ``renewals`` (_renewal), from the root and from every
    reply of a thread not retracted, discussion included.
    """
    m = effective_manifest(state)
    if m is None:
        return []
    channels = channel_ids()
    applied = state.applied_for(state.manifest_root) if checkpointed else None
    return threads_from([ev for ev in state.events.values() if _bound(ev, channels)
                         and (applied is None or ev["id"] in applied)], m, dropped)


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
                           [], _renewal(ev, role)]
    for ev, role, ref in sorted(replies, key=lambda r: (r[0]["created_at"], r[0]["id"])):
        t = roots.get(ref)
        if t is None or t[1]:
            continue
        if (rn := _renewal(ev, role)) is not None:
            t[8].append(rn)
        first = _first_line(ev["content"])
        if role != "curator" and t[3] and not first.startswith("lang:"):
            continue  # discussion: a curator posted or amended this thread (a translation is not)
        if first.startswith("lang:"):  # a translation, never a patch or a retraction
            tr = parse_translation(ev["content"])
            if tr is not None and (tr[1] or ref) in t[6]:  # the root or a change to it
                prev = t[5].setdefault(tr[1] or ref, {}).get(tr[0])
                if role == "curator" or prev is None or not prev[2]:  # a curator's stands
                    t[5][tr[1] or ref][tr[0]] = (tr[2], ev["created_at"], role == "curator")
            continue
        if first == "retract":
            if role == "curator":
                t[1], t[2] = True, ev["created_at"]
            continue
        if first.startswith("level:") and role == "curator":
            want = first[len("level:"):].strip()
            if want in ("high", "notice") and _RANK[want] < _RANK[t[0].level]:
                t[0], t[2], t[3] = replace(t[0], level=want), ev["created_at"], True
                t[6].append(ev["id"])
                t[7] = True
        p = _patch(ev["content"])
        if p is None:
            continue  # convention text only, or discussion
        try:
            new = _apply_patch(t[0], p, role, dropped)
        except Exception:  # a hostile patch never stops the other threads
            new = None
        if new is None:
            dropped["bad-patch"] += 1
            if role != "curator":
                # What a refused patch adds to products, actions or sources
                # still counts: were it lost with the patch, a patch dated
                # earlier that raises the level would take it away.
                p = {k: p[k] for k in _WIDEST if k in p}
                try:
                    new = _apply_patch(t[0], p, role) if p else None
                except Exception:
                    new = None
                if new == t[0]:
                    new = None
        if new is not None:
            t[0], t[2], t[3] = new, ev["created_at"], t[3] or role == "curator"
            if t[6][-1] != ev["id"]:
                t[6].append(ev["id"])
            t[7] = t[7] or "title" in p or "level" in p
            if role == "curator" and "aliases" in p:  # only aliases a curator wrote:
                t[4].update(i.casefold() for i in new.aliases)  # a bot's never list a thread
    listed = {i.casefold() for i in m.retracted}
    out = []
    for rid, (a, r, u, cur, ids, tr, changes, retitled, rns, first) in sorted(
            roots.items(), key=lambda kv: (kv[1][2], kv[0])):
        text, at = _composed(a, tr, changes, retitled)
        ok = ids | {i.casefold() for i in (a.id, *a.aliases)}
        enrolled = first is not None and first[0] in ok
        out.append(Thread(root_id=rid, adv=a, retracted=r or not ids.isdisjoint(listed), updated_at=u,
                          translations=text, translated_at=at, enrolled=enrolled, curated=cur,
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


def active(threads: list[Thread], now: float | None = None, listed=None) -> list[Thread]:
    """Threads check should see: not retracted, not expired, each at the level
    it holds at ``now``.

    ``now`` is the issue time of the newest accepted checkpoint and ``listed``
    the ids it lists (``head_clock``), never this machine's clock: a frozen
    mirror stops the clock, so it can pin an alert and cannot end one. With
    ``now`` None nothing expires; with ``listed`` None every thread counts as
    listed. A thread whose root the checkpoint does not list keeps the level
    its events give.

    A curator's ``expires_at`` ends its thread once ``now`` is past it. A
    thread whose root carries a claim, and that no curator posted or amended,
    is shown at ``ruleset.Ruleset.level_at`` of its renewals dated at or
    before ``now`` (a claim on an event dated after the checkpoint counts
    once a checkpoint reaches its date) and dropped when no level stands.
    Every other thread does not expire. A ruleset that cannot be loaded
    expires nothing."""
    out, rs = [], None
    for t in threads:
        if t.retracted:
            continue
        level = t.adv.level
        if now is not None and (listed is None or t.root_id in listed):
            if t.adv.expires_at is not None:
                if now > t.adv.expires_at:
                    continue
            elif t.enrolled and not t.curated:
                rn = [(c, k) for c, k, at in t.renewals if at <= now]
                try:
                    rs = rs or ruleset.load()
                    level = rs.level_at(level, rn, now) if rn else level
                except Exception:  # a damaged spec file must not end alerts
                    level = t.adv.level
                if level == ruleset.NONE:
                    continue
        out.append(t if level == t.adv.level else replace(t, adv=replace(t.adv, level=level)))
    return out
