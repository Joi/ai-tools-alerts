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
    source_title: str | None = None  # r7hr: the digest line's upstream title; never identity


def _keys(ids) -> set[str]:
    return {i.casefold() for i in ids if isinstance(i, str) and i}


def _strs(v) -> bool:
    return isinstance(v, list) and all(isinstance(i, str) and i for i in v)


def _ids_map(v) -> bool:
    return isinstance(v, dict) and all(isinstance(k, str) and isinstance(i, str) for k, i in v.items())


def _entry_ok(e) -> bool:
    try:
        Entry(**e)
    except TypeError:
        return False
    return (isinstance(e["root_event_id"], str) and _ids_map(e["channel_ids"])
            and e["level"] in schema.LEVELS and _strs(e["aliases"]) and e["aliases"]
            and type(e["posted_at"]) is int and type(e["last_change"]) is int
            and isinstance(e["scope"], str) and type(e["exploited"]) is bool
            and isinstance(e["advisory"], dict)
            and isinstance(e["replies"], list) and all(_ids_map(r) for r in e["replies"])
            and (e.get("source_title") is None or isinstance(e["source_title"], str)))


def _pending_ok(p) -> bool:
    return (isinstance(p, dict) and isinstance(p.get("key"), str) and _strs(p.get("aliases"))
            and type(p.get("at")) is int)


def _review_ok(r) -> bool:
    return (isinstance(r, dict) and isinstance(r.get("text"), str)
            and all(type(r.get(k)) is int for k in ("first_seen", "last_seen", "count")))


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
            self._good = json.dumps(self._data)
        except Exception:
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
            data = json.loads(self.path.read_text(encoding="utf-8"),
                              object_pairs_hook=schema._no_duplicates,
                              parse_constant=schema._reject_constant)
        except FileNotFoundError:
            return {"schema_version": 1, **{k: [] for k in _LISTS}}
        except (OSError, ValueError, RecursionError) as e:
            raise LedgerError(f"ledger {self.path} unreadable: {e}") from None
        if (not isinstance(data, dict) or data.get("schema_version") != 1
                or not all(isinstance(data.get(k), list) for k in _LISTS)
                or not all(_entry_ok(e) for e in data["entries"])
                or not all(_pending_ok(p) for p in data["pending"] + data["expired"])
                or not all(_review_ok(r) for r in data["review"])):
            raise LedgerError(f"ledger {self.path} malformed; refusing to send without dedup")
        return data

    def _state(self) -> dict:
        if self._data is None:
            raise LedgerError("ledger used outside its context (no lock held)")
        return self._data

    def _save(self) -> None:
        data = self._state()
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.")
        replaced = False
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
            replaced = True
            dfd = os.open(self.path.parent, os.O_RDONLY)  # the rename itself survives a crash
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except Exception as e:  # the unsaved change is undone, so no later save writes it
            try:
                os.unlink(tmp)
            except OSError:
                pass
            # Before the rename the disk holds the last good state: undo in memory too.
            # After it, disk and memory may disagree: refuse any further use until reopened.
            self._data = None if replaced else json.loads(self._good)
            raise LedgerError(f"cannot write ledger {self.path}: {e}") from None
        self._good = json.dumps(data)

    # ------------------------------------------------------------ advisories

    def lookup_all(self, aliases, scope: str | None = None) -> list[Entry]:
        """Every entry sharing any id (case-insensitive), oldest first; pass ``scope``
        to stay within one scope entry (a CVE can span several)."""
        want = _keys(aliases)
        hits = [e for e in self._state()["entries"]
                if _keys(e["aliases"]) & want and (scope is None or e["scope"] == scope)]
        return [Entry(**e) for e in sorted(hits, key=lambda e: e["posted_at"])]

    def thread(self, root_event_id: str) -> Entry | None:
        """The entry whose root is ``root_event_id``, or None."""
        for e in self._state()["entries"]:
            if e["root_event_id"] == root_event_id:
                return Entry(**e)
        return None

    def entries_since(self, t: int) -> list[Entry]:
        """Every entry whose last change is after ``t``, oldest change first (the digest)."""
        hits = [e for e in self._state()["entries"] if e["last_change"] > t]
        return [Entry(**e) for e in sorted(hits, key=lambda e: e["last_change"])]

    def lookup(self, aliases, scope: str | None = None) -> Entry | None:
        """The oldest entry sharing any id, optionally for one scope."""
        hits = self.lookup_all(aliases, scope)
        return hits[0] if hits else None

    def _entry(self, root_event_id: str) -> dict:
        for e in self._state()["entries"]:
            if e["root_event_id"] == root_event_id:
                return e
        raise LedgerError(f"no thread {root_event_id}")

    def record_root(self, adv: schema.Advisory, root_event_id: str, channel_ids: dict, *,
                    scope: str, exploited: bool, now: int, ids=(), source_title: str | None = None) -> Entry:
        """A new thread. ``ids`` is the full identity set (the advisory's aliases are
        capped at 50 for publication; the ledger keeps every id)."""
        if not isinstance(root_event_id, str) or not _ids_map(channel_ids):
            raise LedgerError("root_event_id and channel_ids must be strings")
        ids = _union([adv.id, *adv.aliases], ids)
        if self.lookup(ids, scope) is not None:
            raise LedgerError(f"{adv.id} already has a thread; post a reply instead")
        e = dict(root_event_id=root_event_id, channel_ids=dict(channel_ids), level=adv.level,
                 aliases=ids, posted_at=now, last_change=now, scope=scope,
                 exploited=exploited is True, advisory=asdict(adv), replies=[],
                 **({"source_title": source_title} if source_title else {}))
        self._state()["entries"].append(e)
        self._save()
        return Entry(**e)

    def add_channel(self, root_event_id: str, channel: str, event_id: str) -> Entry:
        """Record the root in one more channel (a critical posts to two, one at a time)."""
        if not (isinstance(channel, str) and isinstance(event_id, str)):
            raise LedgerError("channel and event_id must be strings")
        e = self._entry(root_event_id)
        e["channel_ids"][channel] = event_id
        self._save()
        return Entry(**e)

    def add_ids(self, root_event_id: str, ids) -> Entry:
        """Learn more ids for a thread without a post (identity is not capped)."""
        e = self._entry(root_event_id)
        merged = _union(e["aliases"], ids)
        if merged != e["aliases"]:
            e["aliases"] = merged
            self._save()
        return Entry(**e)

    def learn_title(self, root_event_id: str, title: str) -> None:
        """A source title learned after the root posted: kept for the digest, never posted."""
        e = self._entry(root_event_id)
        if not e.get("source_title") and isinstance(title, str) and title:
            e["source_title"] = title
            self._save()

    def record_reply(self, root_event_id: str, adv: schema.Advisory, reply_ids: dict, *,
                     now: int, exploited: bool = False, ids=()) -> Entry:
        if not _ids_map(reply_ids):
            raise LedgerError("reply_ids must map channel to event id")
        e = self._entry(root_event_id)
        e["aliases"] = _union(e["aliases"], [adv.id, *adv.aliases, *ids])
        e.update(level=adv.level, advisory=asdict(adv), last_change=now,
                 exploited=e["exploited"] or exploited is True)
        e["replies"].append(dict(reply_ids))
        self._save()
        return Entry(**e)

    # ------------------------------------------------------------ in-flight sends

    def has_pending(self, key: str) -> bool:
        return any(p["key"] == key for p in self._state()["pending"])

    def has_event(self, event_id: str) -> bool:
        """True when any thread already records ``event_id`` (root, channel copy or reply)."""
        return any(event_id == e["root_event_id"] or event_id in e["channel_ids"].values()
                   or any(event_id in r.values() for r in e["replies"])
                   for e in self._state()["entries"])

    def pending_entries(self) -> list[dict]:
        """Every send in flight (copies), oldest first: ``aitools-alerts-poster pending``."""
        return sorted((dict(p) for p in self._state()["pending"]), key=lambda p: p["at"])

    def pending_for(self, aliases) -> list[dict]:
        want = _keys(aliases)
        return [p for p in self._state()["pending"] if _keys(p["aliases"]) & want]

    def pending(self, key: str, aliases, *, now: int) -> None:
        """Record a send as in flight, on disk, before it happens. Refuses when the
        same key or any of the advisory's ids is already in flight."""
        st = self._state()
        aliases = [a for a in aliases if isinstance(a, str) and a]
        blocking = [p for p in st["pending"] if p["key"] == key] + self.pending_for(aliases)
        if blocking:
            for p in blocking:  # keep the ids learned now, so a later candidate under any of them is held too
                p["aliases"] = sorted(set(_union(p["aliases"], aliases)))
            self._save()
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


def _union(a, b) -> list[str]:
    out = list(a)
    seen = _keys(out)
    for i in b:
        if isinstance(i, str) and i and i.casefold() not in seen:
            seen.add(i.casefold())
            out.append(i)
    return out


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
    ids = _union([], (a for c in members for a in (c.id, *c.aliases)))
    sources, urls = [], set()
    for c in members:
        for s in c.sources:
            if s.url not in urls:
                urls.add(s.url)
                sources.append(s)
    exploited = any(c.exploited is True for c in members)
    if ledger is not None and not exploited:  # any stored entry of this scope, not only the oldest
        exploited = any(e.exploited is True for e in ledger.lookup_all(ids, scope_name))
    # fixed and affected come from one member, preferring a fix the schema can publish.
    fix = next((c for c in members if schema._FIXED.fullmatch((c.fixed or "").lstrip("vV"))),
               next((c for c in members if c.fixed),
                    next((c for c in members if c.affected), first)))
    severities = [c.advisory_severity for c in members if isinstance(c.advisory_severity, str)]
    return replace(
        first, aliases=tuple(a for a in ids if a != first.id),
        exploited=exploited,
        source_title=next((c.source_title for c in members if getattr(c, "source_title", None)), None),
        trojanized=any(c.trojanized is True for c in members),
        injection_exec=any(c.injection_exec is True for c in members),
        fixed=fix.fixed, affected=fix.affected,
        # every member's severity text, so B2's rule sees it whichever order (never published)
        advisory_severity="; ".join(dict.fromkeys(severities)) or None,
        sources=tuple(sources))
