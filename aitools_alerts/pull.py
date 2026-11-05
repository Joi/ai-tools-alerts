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
from .state import State

__all__ = ["FILES", "MAX_FETCH_BYTES", "MAX_EVENTS", "PullResult", "Thread",
           "fetch", "default_fetch", "advisories", "active", "bundled_manifest"]

FILES = ("feed.json", "critical.json")
MAX_FETCH_BYTES = 8 << 20
MAX_EVENTS = 10000
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
    cands = []
    if state.manifest is not None and state.manifest_root == root:
        cands.append(state.manifest)
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
    """Pull the mirror at ``base_url`` into ``state`` (saved on success only)."""
    get = fetch or default_fetch
    now = time.time() if now is None else now
    base = base_url if base_url.endswith("/") else base_url + "/"
    floor = _floor(state, root_pubkey)
    res = PullResult(manifest=state.manifest if state.manifest_root == root_pubkey else floor)

    def fail(msg: str) -> PullResult:
        res.error = msg
        state.last_pull = {**{k: v for k, v in state.last_pull.items() if k == "last_ok_at"},
                           "at": int(now), "mirror_url": base, "ok": False, "error": msg}
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
    fetched = []
    for name in FILES:
        try:
            fetched += _events_file(get(base + name), name)
        except ValueError as e:
            return fail(f"mirror unreadable: {e}")
        except Exception as e:
            return fail(f"mirror unreadable: {name}: {e}")
    # 4. every candidate, stored or fetched, under the current manifest only
    before = state.events
    cands: dict[str, dict] = {}
    for ev in list(before.values()) + fetched:
        if not isinstance(ev, dict) or not isinstance(ev.get("id"), str):
            res.dropped["malformed"] += 1
            continue
        cands.setdefault(ev["id"], ev)
    kept: dict[str, dict] = {}
    for eid, ev in cands.items():
        if not nostr.verify_event(ev):
            res.dropped["bad-signature"] += 1
        elif manifest.role_of(m, ev["pubkey"]) is None:
            was = (eid in before or (floor is not None
                                     and manifest.role_of(floor, ev["pubkey"]) is not None))
            res.dropped["revoked" if was else "unknown-poster"] += 1
        else:
            kept[eid] = copy.deepcopy(ev)
    # 5. save
    res.new_events = sorted((ev for eid, ev in kept.items() if eid not in before),
                            key=lambda e: (e["created_at"], e["id"]))
    res.manifest = m
    state.events, state.manifest, state.manifest_root = kept, m, root_pubkey
    state.last_pull = {"at": int(now), "last_ok_at": int(now), "mirror_url": base, "ok": True,
                       "error": None, "new": len(res.new_events), "dropped": dict(res.dropped)}
    state.save_pull()
    return res


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
    nullable fields validate as null). posted_by is ignored; id must match."""
    if not patch or set(patch) - _PATCH_KEYS:
        return None
    if "id" in patch and patch["id"] != adv.id:
        return None
    patch = {k: v for k, v in patch.items() if k != "posted_by"}
    if role != "curator" and "level" in patch and _RANK.get(patch["level"], 0) < _RANK[adv.level]:
        del patch["level"]  # only a curator may lower a level
    merged = {**asdict(adv), **patch}
    if role != "curator":
        merged["posted_by"] = "relay-bot"  # least trusted author wins
    try:
        return schema.validate(merged)
    except ValueError:
        return None


def advisories(state: State, dropped: Counter | None = None) -> list[Thread]:
    """Every thread built from the stored events under the stored manifest."""
    m = state.manifest
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
        roots[ev["id"]] = [replace(adv, posted_by=role), False, ev["created_at"]]
    for ev, role, ref in sorted(replies, key=lambda r: (r[0]["created_at"], r[0]["id"])):
        t = roots.get(ref)
        if t is None or t[1]:
            continue
        adv = t[0]
        first = ev["content"].strip().split("\n", 1)[0].strip() if ev["content"].strip() else ""
        if first == "retract":
            if role == "curator":
                t[1], t[2] = True, ev["created_at"]
            continue
        if first.startswith("level:"):
            if role == "curator":
                want = first[len("level:"):].strip()
                if want in ("high", "notice") and _RANK[want] < _RANK[adv.level]:
                    t[0], t[2] = replace(adv, level=want), ev["created_at"]
            continue
        p = _patch(ev["content"])
        if p is None:
            continue  # discussion
        new = _apply_patch(adv, p, role)
        if new is None:
            dropped["bad-patch"] += 1
        else:
            t[0], t[2] = new, ev["created_at"]
    return [Thread(root_id=rid, adv=a, retracted=r, updated_at=u)
            for rid, (a, r, u) in sorted(roots.items(), key=lambda kv: (kv[1][2], kv[0]))]


def active(threads: list[Thread], now: float | None = None) -> list[Thread]:
    """Threads check should see: not retracted, not expired."""
    now = time.time() if now is None else now
    return [t for t in threads if not t.retracted
            and (t.adv.expires_at is None or t.adv.expires_at >= now)]
