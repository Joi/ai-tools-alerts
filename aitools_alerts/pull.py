"""Fetch the signed mirror, decide which events to believe, build advisories.

Verification order, every pull: the manifest is signed by the trust root and
is not older than the one already accepted (or the bundled one); then each
event's signature; then the event's key must be in the CURRENT manifest; the
post block is parsed last, when advisories are built. ``posted_by`` always
comes from the manifest role of the event's key, never from the block.

A pull that fails anywhere before the save changes no event, manifest or
seen record: a truncated or half-written mirror file is "mirror unreadable",
never an empty feed. Stored events are re-checked against the current
manifest on every pull, so a key removed from the manifest loses its events.
"""

from __future__ import annotations

import copy
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from urllib.parse import urlsplit

from . import TRUST_DIR, TRUST_ROOT_PUBKEY, manifest, nostr, schema
from .manifest import Manifest
from .schema import Advisory
from .state import EVENT_KEYS, State

__all__ = ["FILES", "MAX_FETCH_BYTES", "MAX_EVENTS", "PullResult", "Thread",
           "fetch", "default_fetch", "advisories", "active", "bundled_manifest"]

FILES = ("feed.json", "critical.json")
MAX_FETCH_BYTES = 8 << 20
MAX_EVENTS = 10000
MAX_STORED_EVENTS = 20000
MAX_STORED_BYTES = 32 << 20  # serialized, all roots; half state.MAX_STATE_BYTES
RETENTION_S = 400 * 86400
TIMEOUT = 20
_RANK = {"notice": 1, "high": 2, "critical": 3}
_PATCH_KEYS = frozenset(f for f in Advisory.__dataclass_fields__)


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


# ------------------------------------------------------------------ fetching

class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError(f"refused redirect to {urlsplit(newurl).scheme or 'a relative'} URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirect)


def default_fetch(url: str) -> bytes:
    """GET an https:// or file:// URL; at most MAX_FETCH_BYTES. Raises OSError."""
    scheme = urlsplit(url).scheme
    if scheme not in ("https", "file"):
        raise OSError(f"refused URL scheme {scheme or '(none)'}: only https and file")
    req = urllib.request.Request(url, headers={"User-Agent": "aitools-alerts"})
    try:
        with _OPENER.open(req, timeout=TIMEOUT) as r:
            data = r.read(MAX_FETCH_BYTES + 1)
    except urllib.error.URLError as e:
        raise OSError(str(getattr(e, "reason", e))) from None
    except ValueError as e:  # malformed URL
        raise OSError(str(e)) from None
    if len(data) > MAX_FETCH_BYTES:
        raise OSError(f"larger than {MAX_FETCH_BYTES} bytes")
    return data


def bundled_manifest() -> Manifest | None:
    """The manifest shipped in trust/, if it verifies under the pinned root."""
    try:
        m = manifest.load(TRUST_DIR / "manifest.json")
    except manifest.ManifestError:
        return None
    return m if manifest.verify(m, TRUST_ROOT_PUBKEY) else None


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
          now: float | None = None) -> PullResult:
    """Pull the mirror at ``base_url`` into ``state`` under the state lock."""
    with state.locked():
        return _fetch(base_url, state, fetch or default_fetch, root_pubkey,
                      time.time() if now is None else now)


def _filter(stored: dict, fetched: list, m: Manifest, floor: Manifest | None,
            res: PullResult) -> dict:
    """Events whose key is in ``m``: the stored ones (verified when they were
    stored), then each fetched one that verifies. A fetched event is verified
    before it can claim its id, so a forged copy of a genuine id never
    displaces the genuine one. Only the seven NIP-01 fields are kept: an
    unsigned extra field never reaches state."""
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
        else:
            kept[eid] = {k: copy.deepcopy(ev[k]) for k in EVENT_KEYS}
            why.pop(eid, None)
    res.dropped.update(why.values())
    return kept


def _retain(kept: dict, now: float, res: PullResult) -> dict:
    """Drop whole threads (a root and every reply to it) whose newest event
    is older than RETENTION_S. A thread is kept or dropped as a unit, so a
    retraction, a patch or a curator amendment never outlives or predeceases
    its thread."""
    cutoff = now - RETENTION_S
    newest: dict[str, int] = {}
    for eid, ev in kept.items():
        key = _thread_ref(ev) or eid
        newest[key] = max(newest.get(key, 0), ev["created_at"])
    out = {eid: ev for eid, ev in kept.items() if newest[_thread_ref(ev) or eid] >= cutoff}
    if len(out) < len(kept):
        res.dropped["aged-out"] += len(kept) - len(out)
    return out


def _fetch(base_url, state: State, get, root_pubkey: str, now: float) -> PullResult:
    base = base_url if base_url.endswith("/") else base_url + "/"
    floor = _floor(state, root_pubkey)
    res = PullResult(manifest=state.accepted(root_pubkey) or floor)
    before = state.events_for(root_pubkey)

    def record(ok: bool, error: str | None) -> None:
        last = {"at": int(now), "mirror_url": base, "ok": ok, "error": error,
                "last_ok_at": int(now) if ok else state.last_pull.get("last_ok_at")}
        if ok:
            last.update(new=len(res.new_events), dropped=dict(res.dropped))
        state.last_pull = last

    def fail(msg: str) -> PullResult:
        res.error = msg
        record(False, msg)
        state.save_last_pull()
        return res

    # 1. manifest: well formed, not older than the floor
    try:
        m = manifest.load(get(base + "manifest.json"), previous=floor)
    except manifest.ManifestError as e:
        return fail(f"manifest refused: {e}")
    except Exception as e:
        return fail(f"manifest unreadable: {e}")
    if floor is not None and m.issued_at < floor.issued_at:
        return fail(f"manifest refused: issued_at {m.issued_at} is older than the accepted {floor.issued_at}")
    # 2. signed by the trust root
    if not manifest.verify(m, root_pubkey):
        return fail("manifest not signed by the trust root")
    # 3. both event files, whole
    fetched, error = [], None
    for name in FILES:
        try:
            fetched += _events_file(get(base + name), name)
        except ValueError as e:
            error = f"mirror unreadable: {e}"
        except Exception as e:
            error = f"mirror unreadable: {name}: {e}"
        if error:
            break
    # 4. stored events first, then fetched, under the current manifest only.
    # A verified manifest is accepted even when an event file is unreadable
    # or the store is full: its revocations apply to the stored events at
    # once, while the previous events of keys it still trusts are kept.
    res.manifest = m
    kept = _retain(_filter(before, [] if error else fetched, m, floor, res), now, res)
    if (len(kept) > MAX_STORED_EVENTS
            or state.size_with(root_pubkey, m, kept) > MAX_STORED_BYTES):
        res.dropped.clear()
        kept = _retain(_filter(before, [], m, floor, res), now, res)
        error = error or "state limit reached: new events not stored"
    res.new_events = sorted((ev for eid, ev in kept.items() if eid not in before),
                            key=lambda e: (e["created_at"], e["id"]))
    state.accept(root_pubkey, m, kept)
    res.error = error
    record(error is None, error)
    state.save_pull()
    return res


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


def _apply_patch(adv: Advisory, patch: dict, role: str) -> Advisory | None:
    """The advisory with ``patch`` applied, or None if the patch is invalid.
    Omitted field: unchanged. Present: replaced whole. null: cleared (only
    nullable fields validate as null). ``posted_by`` is ignored (the thread
    keeps its root's role); ``id`` must match. A relay-bot patch may not
    lower ``level`` or set ``expires_at`` (both would hide an alert)."""
    if not patch or set(patch) - _PATCH_KEYS:
        return None
    if "id" in patch and patch["id"] != adv.id:
        return None
    patch = {k: v for k, v in patch.items() if k != "posted_by"}
    if role != "curator":
        if "expires_at" in patch:
            return None
        lvl = patch.get("level", adv.level)
        if not isinstance(lvl, str) or lvl not in _RANK or _RANK[lvl] < _RANK[adv.level]:
            return None
    try:
        return schema.validate({**asdict(adv), **patch, "posted_by": adv.posted_by})
    except ValueError:
        return None


def _first_line(content: str) -> str:
    return content.strip().split("\n", 1)[0].strip()


def advisories(state: State, dropped: Counter | None = None) -> list[Thread]:
    """Every thread built from the stored events under the current manifest.

    Replies apply to their root in (created_at, id) order. A curator reply
    whose first line is ``retract`` retracts the thread for good; one whose
    first line is ``level: high`` or ``level: notice`` lowers the level. A
    reply's ``aitools-alert`` block, if any, is a patch (see _apply_patch).
    Once a curator has posted or amended a thread, a relay-bot reply to it is
    discussion, so the bot can neither suppress, alter nor undo a curator's
    word. A patch that fails validation, or raises, is counted and skipped.
    """
    m = effective_manifest(state)
    if m is None:
        return []
    dropped = dropped if dropped is not None else Counter()
    roots, replies = {}, []
    for ev in state.events.values():
        role = manifest.role_of(m, ev.get("pubkey"))
        if role is None:
            continue
        ref = _thread_ref(ev)
        if ref is not None:
            replies.append((ev, role, ref))
            continue
        adv = schema.parse_post(ev["content"])
        if adv is None:
            dropped["no-block"] += 1
            continue
        roots[ev["id"]] = [replace(adv, posted_by=role), False, ev["created_at"], role == "curator"]
    for ev, role, ref in sorted(replies, key=lambda r: (r[0]["created_at"], r[0]["id"])):
        t = roots.get(ref)
        if t is None or t[1]:
            continue
        if role != "curator" and t[3]:
            continue  # discussion: a curator posted or amended this thread
        first = _first_line(ev["content"])
        if first == "retract":
            if role == "curator":
                t[1], t[2] = True, ev["created_at"]
            continue
        if first.startswith("level:") and role == "curator":
            want = first[len("level:"):].strip()
            if want in ("high", "notice") and _RANK[want] < _RANK[t[0].level]:
                t[0], t[2], t[3] = replace(t[0], level=want), ev["created_at"], True
        p = _patch(ev["content"])
        if p is None:
            continue  # convention text only, or discussion
        try:
            new = _apply_patch(t[0], p, role)
        except Exception:  # a hostile patch never stops the other threads
            new = None
        if new is None:
            dropped["bad-patch"] += 1
        else:
            t[0], t[2], t[3] = new, ev["created_at"], t[3] or role == "curator"
    return [Thread(root_id=rid, adv=a, retracted=r, updated_at=u)
            for rid, (a, r, u, _) in sorted(roots.items(), key=lambda kv: (kv[1][2], kv[0]))]


def active(threads: list[Thread], now: float | None = None) -> list[Thread]:
    """Threads check should see: not retracted, not expired."""
    now = time.time() if now is None else now
    return [t for t in threads if not t.retracted
            and (t.adv.expires_at is None or t.adv.expires_at >= now)]
