"""The poster's advisory ledger: what was posted, what is in flight, what needs a human.

Dedup discipline (as security_route.py in amplifier-bundle-joi): a run holds an
exclusive lock beside the ledger from load to last write; a ``pending`` entry is
on disk before a send, and blocks any resend of that advisory until it is
cleared after a known outcome or explicitly expired after 24 hours with a
logged reason. A missing ledger is empty; a malformed one is refused, because
sending without dedup could interrupt members twice. Writes are atomic.
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import tempfile
import unicodedata
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from aitools_alerts import schema

DEFAULT_PATH = Path.home() / ".local" / "state" / "aitools-alerts-poster" / "ledger.json"
PENDING_EXPIRY = 24 * 3600
MAX_REVIEW = 500
MAX_REVIEW_TEXT = 300
_LISTS = ("entries", "pending", "expired", "review")
log = logging.getLogger(__name__)


class LedgerError(RuntimeError):
    """The ledger cannot be used safely; the caller must not send."""


@dataclass(frozen=True)
class Entry:
    root_event_id: str
    channel_ids: dict
    level: str
    aliases: list
    posted_at: int
    last_change: int
    scope: str
    exploited: bool
    advisory: dict
    replies: list


def _keys(ids) -> set[str]:
    return {i.casefold() for i in ids if isinstance(i, str) and i}


def _entry_ok(e) -> bool:
    try:
        Entry(**e)
    except TypeError:
        return False
    return (isinstance(e["root_event_id"], str) and isinstance(e["channel_ids"], dict)
            and isinstance(e["aliases"], list) and isinstance(e["scope"], str)
            and isinstance(e["advisory"], dict) and isinstance(e["replies"], list))


class Ledger:
    def __init__(self, path=DEFAULT_PATH):
        self.path = Path(path)
        self._lock = None
        self._data = None

    # ------------------------------------------------------------ lifecycle

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        lock = self.path.with_name(self.path.name + ".lock")
        fh = open(lock, "a")
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            raise LedgerError(f"another poster run holds {lock}") from None
        try:
            self._data = self._load()
        except LedgerError:
            fh.close()
            raise
        self._lock = fh
        return self

    def __exit__(self, *exc):
        self._data = None
        if self._lock:
            self._lock.close()
            self._lock = None

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"schema_version": 1, **{k: [] for k in _LISTS}}
        except (OSError, ValueError) as e:
            raise LedgerError(f"ledger {self.path} unreadable: {e}") from None
        if (not isinstance(data, dict) or data.get("schema_version") != 1
                or not all(isinstance(data.get(k), list) for k in _LISTS)
                or not all(_entry_ok(e) for e in data["entries"])
                or not all(isinstance(p, dict) and isinstance(p.get("key"), str)
                           and isinstance(p.get("aliases"), list) and type(p.get("at")) is int
                           for p in data["pending"])):
            raise LedgerError(f"ledger {self.path} malformed; refusing to send without dedup")
        return data

    def _state(self) -> dict:
        if self._data is None:
            raise LedgerError("ledger used outside its context (no lock held)")
        return self._data

    def _save(self) -> None:
        data = self._state()
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
            dfd = os.open(self.path.parent, os.O_RDONLY)  # the rename itself survives a crash
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise LedgerError(f"cannot write ledger {self.path}: {e}") from None

    # ------------------------------------------------------------ advisories

    def lookup(self, aliases, scope: str | None = None) -> Entry | None:
        """The oldest entry sharing any id (case-insensitive), optionally for one scope."""
        want = _keys(aliases)
        hits = [e for e in self._state()["entries"]
                if _keys(e["aliases"]) & want and (scope is None or e["scope"] == scope)]
        return Entry(**min(hits, key=lambda e: e["posted_at"])) if hits else None

    def record_root(self, adv: schema.Advisory, root_event_id: str, channel_ids: dict, *,
                    scope: str, exploited: bool, now: int) -> Entry:
        ids = [adv.id, *adv.aliases]
        if self.lookup(ids, scope) is not None:
            raise LedgerError(f"{adv.id} already has a thread; post a reply instead")
        e = dict(root_event_id=root_event_id, channel_ids=dict(channel_ids), level=adv.level,
                 aliases=ids, posted_at=now, last_change=now, scope=scope,
                 exploited=exploited is True, advisory=asdict(adv), replies=[])
        self._state()["entries"].append(e)
        self._save()
        return Entry(**e)

    def record_reply(self, root_event_id: str, adv: schema.Advisory, reply_ids: dict, *,
                     now: int, exploited: bool = False) -> Entry:
        for e in self._state()["entries"]:
            if e["root_event_id"] == root_event_id:
                break
        else:
            raise LedgerError(f"no thread {root_event_id}")
        e["aliases"] += [a for a in [adv.id, *adv.aliases] if a.casefold() not in _keys(e["aliases"])]
        e.update(level=adv.level, advisory=asdict(adv), last_change=now,
                 exploited=e["exploited"] or exploited is True)
        e["replies"].append(dict(reply_ids))
        self._save()
        return Entry(**e)

    # ------------------------------------------------------------ in-flight sends

    def pending_for(self, aliases) -> list[dict]:
        want = _keys(aliases)
        return [p for p in self._state()["pending"] if _keys(p["aliases"]) & want]

    def pending(self, key: str, aliases, *, now: int) -> None:
        """Record a send as in flight, on disk, before it happens. Refuses when the
        same key or any of the advisory's ids is already in flight."""
        st = self._state()
        if any(p["key"] == key for p in st["pending"]) or self.pending_for(aliases):
            raise LedgerError(f"{key}: a send is already in flight; never resent until cleared or expired")
        st["pending"].append({"key": key, "aliases": sorted(set(aliases)), "at": now})
        self._save()

    def _take(self, key: str) -> dict:
        st = self._state()
        for i, p in enumerate(st["pending"]):
            if p["key"] == key:
                return st["pending"].pop(i)
        raise LedgerError(f"{key}: nothing pending")

    def clear_pending(self, key: str) -> None:
        """Remove a pending entry once the send's outcome is known."""
        self._take(key)
        self._save()

    def expire_pending(self, key: str, reason: str, *, now: int) -> None:
        """Drop a pending entry at least 24 hours old, recording why."""
        if not isinstance(reason, str) or not reason.strip():
            raise LedgerError("expiring a pending send needs a reason")
        p = next((p for p in self._state()["pending"] if p["key"] == key), None)
        if p is None:
            raise LedgerError(f"{key}: nothing pending")
        if now - p["at"] < PENDING_EXPIRY:
            raise LedgerError(f"{key}: pending for under 24 hours; cannot expire yet")
        self._take(key)
        self._state()["expired"].append({**p, "expired_at": now, "reason": reason.strip()})
        log.warning("expired pending send %s after %ss: %s", key, now - p["at"], reason.strip())
        self._save()

    # ------------------------------------------------------------ review

    def add_review(self, texts, *, now: int) -> None:
        """Keep B2's unmatched tier-1 vendor texts, deduplicated, for a human."""
        review = self._state()["review"]
        by_text = {r.get("text"): r for r in review if isinstance(r, dict)}
        for t in texts:
            if not isinstance(t, str):
                continue
            t = "".join(ch for ch in t if unicodedata.category(ch)[0] != "C").strip()[:MAX_REVIEW_TEXT]
            if not t:
                continue
            r = by_text.get(t)
            if r is None:
                r = by_text[t] = {"text": t, "first_seen": now, "last_seen": now, "count": 0}
                review.append(r)
            r["count"] += 1
            r["last_seen"] = max(r["last_seen"], now)
        del review[:-MAX_REVIEW]
        self._save()


# ---------------------------------------------------------------- alias merge


def merge(pairs, ledger: Ledger | None = None) -> list:
    """Merge (Candidate, ScopeEntry) pairs that share an id or alias under the same
    scope entry. ``exploited`` crosses only within one scope: a candidate under
    another scope never inherits the KEV clause, even if it names the KEV CVE."""
    out = []
    by_scope: dict[str, list] = {}
    for c, s in pairs:
        by_scope.setdefault(s.name, []).append((c, s))
    for name, group in by_scope.items():
        parent = list(range(len(group)))

        def root(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        seen: dict[str, int] = {}
        for i, (c, _) in enumerate(group):
            for k in _keys([c.id, *c.aliases]):
                if k in seen:
                    parent[root(i)] = root(seen[k])
                else:
                    seen[k] = i
        comps: dict[int, list] = {}
        for i in range(len(group)):
            comps.setdefault(root(i), []).append(group[i][0])
        for members in comps.values():
            out.append((_merged(members, name, ledger), group[0][1]))
    return out


def _merged(members, scope_name, ledger):
    first = members[0]
    ids = []
    for c in members:
        for a in (c.id, *c.aliases):
            if a.casefold() not in _keys(ids):
                ids.append(a)
    sources, urls = [], set()
    for c in members:
        for s in c.sources:
            if s.url not in urls:
                urls.add(s.url)
                sources.append(s)
    exploited = any(c.exploited is True for c in members)
    if ledger is not None and not exploited:
        e = ledger.lookup(ids, scope_name)
        exploited = e is not None and e.exploited is True
    return replace(
        first, aliases=tuple(a for a in ids if a != first.id),
        exploited=exploited,
        trojanized=any(c.trojanized is True for c in members),
        injection_exec=any(c.injection_exec is True for c in members),
        fixed=next((c.fixed for c in members if c.fixed), None),
        affected=next((c.affected for c in members if c.affected), None),
        sources=tuple(sources))
